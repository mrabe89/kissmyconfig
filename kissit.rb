#!/usr/bin/env ruby
#
# Copyright (c) 2018 Matthias Rabe <mrabe@hatdev.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

require 'getoptlong'
require 'yaml'
require 'readline'
require 'pry-rescue'
require 'net/ssh'
require 'net/scp'

VERSION = "0.0.1"

# const
$gvars = {verbose: false, force: false, verify: true, debug_tasks: false, refmt: false}
$desc = nil
$default_subtasks = "prep:install:config"

# class
class KissIt
end

class KissItHost < KissIt
	def hostname;	return @cfg[:hostname];		end
	def ip;		return @cfg[:ip];		end
	def password;	return @cfg[:password];		end
	def user;	return @cfg[:user] || "root";	end
	def sudo;	return @cfg[:sudo];		end
	def wants;	return @wants;			end

	def set(hostname, hostdesc)
		@cfg = {hostname: hostname, ip: nil, password: nil, user: nil, sudo: nil}
		@wants = []
		@connection = nil

		hostdesc.each {|hostdefname, hostdefval|
			case hostdefname
			when "ip", "password", "user", "sudo"
				raise "#{hostname} #{hostdefname} is not a string" if hostdefval.class != String
				case hostdefname
				when "ip"	then @cfg[:ip]		= hostdefval
				when "password"	then @cfg[:password]	= hostdefval
				when "user"	then @cfg[:user]	= (hostdefval == "@" ? `whoami`.strip : hostdefval)
				when "sudo"	then @cfg[:sudo]	= hostdefval
				end
			when "wants"
				hostdefval = [hostdefval] if hostdefval.class != Array
				hostdefval.each_with_index {|w, i|
					@wants.push(w.class != Array ? [w] : w)
				}
			when "nowants"
				# isnt handled so its not validated
			else
				raise "hostdefname #{hostdefname} not allowed in (in #{hostname})"
			end
		}

		return self
	end

	def exec(cmd, opts= {})
		connect() if not @connection
		@connection.exec(cmd, opts)
	end

	def cp(localfname, remotefname)
		connect() if not @connection
		@connection.cp(localfname, remotefname)
	end

	def connect()
		if @cfg[:ip]
			@connection = KissItConnectionSSH.new.connect(self)
		else
			raise "IP missing for #{hostname}"
		end
	end

	def disconnect()
		@connection.disconnect()
		@connection = nil
	end
end

class KissItTask < KissIt
	def taskname;	return @cfg[:taskname];	end

	def set(taskname, taskdesc)
		@cfg = {taskname: taskname}
		@subs = {}
		$gvars[:subtasks].each {|s| @subs[s.to_sym] = nil }

		taskdesc.each {|subtaskname, subtaskdesc|
			raise "subtaskname #{subtaskname} not allowed (in #{taskname})" \
					if not $gvars[:subtasks].include? subtaskname
			@subs[subtaskname.to_sym] = KissItTaskSub.new.set(self, subtaskname, subtaskdesc)
		}

		return self
	end

	def exec(host, args = [])
		binding.pry if $gvars[:debug_tasks]

		$gvars[:subtasks].each {|subtask| subtask = subtask.to_sym
			next if @subs[subtask].nil?
			@subs[subtask].exec(host, args)
		}
		$stderr.puts  " ### OK"

		binding.pry if $gvars[:debug_tasks]
	end
end

class KissItTaskSub < KissIt
	def subtaskname;	return @cfg[:subtaskname];	end

	def set(parent, subtaskname, subtaskdesc)
		@cfg = {subtaskname: subtaskname}
		@parent = parent
		@desc = {}

		subtaskdesc.each{|subsubtaskname, subsubtaskdesc|
			case subsubtaskname
			when "state", "pre", "post"
				subsubtaskdesc = [subsubtaskdesc] if subsubtaskdesc.class != Array
			when "cp"
				subsubtaskdesc.each {|cp, cpdesc|
					if cpdesc.class != Array
						subsubtaskdesc[cp] = [cpdesc]
					else
						raise "subsubtaskname #{subsubtaskname} has too many parameter " +
								"for #{cp.inspect} " +
								"(in #{taskname}/#{subtaskname})" if cpdesc.size > 3
					end
				}
			when "flags"
				subsubtaskdesc = [subsubtaskdesc] if subsubtaskdesc.class != Array
				subsubtaskdesc.each {|f|
					next if [:will_lose_connection, :sleep_10, :sleep_30, :sleep_60].include? f
					raise "subsubtaskname #{subsubtaskname} has a unknown flag (#{f.inspect}) " +
							"(in #{taskname}/#{subtaskname})"
				}
			else
				raise "subsubtaskname #{subsubtaskname} not allowed (in #{taskname}/#{subtaskname})"
			end

			@desc[subsubtaskname.to_sym] = subsubtaskdesc
		}

		return self
	end

	def exec(host, args = [])
		$stderr.puts " ### DO #{@parent.taskname}/#{subtaskname}"

		return if hndl_task_state_ck(host, args) == :skip

		hndl_task_exec(host, args, :pre)
		hndl_task_upload(host, args)
		hndl_task_exec(host, args, :post)

		hndl_task_state_ck(host, args, false)

		if @cfg[:flags]
			($stderr.puts "   ### sleep 10"; sleep 10) if @desc[:flags].include? :sleep_10
			($stderr.puts "   ### sleep 30"; sleep 30) if @desc[:flags].include? :sleep_30
			($stderr.puts "   ### sleep 60"; sleep 60) if @desc[:flags].include? :sleep_60
		end

		$stderr.puts  "   ### OK"
	end

	def hndl_task_state_ck(host, args, preck= true)
		return :ok if (preck and $gvars[:force]) or (not preck and not $gvars[:verify])
		return :ok if not @desc[:state] and not @desc[:cp]

		$stderr.puts  "   ### Check #{preck ? "State" : "Success"}"
		ret = 0

		if @desc[:state]
			@desc[:state].each {|cmd|
				ret = host.exec(complete_cmd(host, args, cmd), {error_is_ok: 1})
				break if not ret.zero?
			}
		end

		if @desc[:cp] and ret == 0
			@desc[:cp].each {|localfname, remotedesc|
				md5_local = `md5sum '#{get_localfname(host, args, localfname)}'`
				ret, md5_remote = host.exec("md5sum '#{get_remotefname(host, args, remotedesc[0])}'", {error_is_ok: 1, ret_output: 1});
				verbose("     ### #{md5_local}")
				verbose("     ### #{md5_remote}")
				($stderr.puts "     ### #{md5_local} -> MD5 mismatch or missing"; ret = 1) \
					if not ret.zero? or (md5_local.split[0] != md5_remote.split[0])
				break if not ret.zero?
			}
		end

		($stderr.puts "   ### Nothing to do"; return :skip) if preck and ret.zero?
		($stderr.puts "!!!!!! FAILED : state condition not satisfied after completion"; exit 1) if not preck and not ret.zero?

		return :ok
	end

	def hndl_task_exec(host, args, subsubtask)
		if @desc[subsubtask]
			$stderr.puts "   ### Perform Actions (#{subsubtask})"
			@desc[subsubtask].each {|cmd| host.exec(complete_cmd(host, args, cmd), @desc[:flags]) }
		end
	end

	def hndl_task_upload(host, args)
		if @desc[:cp]
			$stderr.puts "   ### Uploading Files"

			@desc[:cp].each {|localfname, remotedesc|
				localfname = get_localfname(host, args, localfname)
				remotefname = get_remotefname(host, args, remotedesc[0])

				if host.sudo
					tmp_fname="/tmp/kms_#{rand(36**8).to_s(36)}"
					$stderr.puts "     ### Upload: #{localfname} to #{tmp_fname}"
					host.cp(localfname, tmp_fname)
					$stderr.puts "     ### Renaming to #{remotefname}"
					host.exec("mv #{tmp_fname} '#{remotefname}'")
				else
					$stderr.puts "     ### Upload: #{localfname} to #{remotefname}"
					host.cp(localfname, remotefname)
				end

				if remotedesc[1]
					if remotedesc[1] != "@"
						host.exec("chown #{complete_cmd(host, args, remotedesc[1])} '#{remotefname}'")
					else
						host.exec("chown #{host.user} '#{remotefname}'")
					end
				end
				host.exec("chmod #{complete_cmd(host, args, remotedesc[2])} '#{remotefname}'") if remotedesc[2]
			}
		end
	end

	def get_localfname(host, args, fname)
		fname = complete_cmd(host, args, fname)

		return "#{host.hostname}/#{fname}" if File.exist?("#{host.hostname}/#{fname}")
		return fname if File.exist?(fname)

		raise "local file '#{fname}' not found"
	end

	def get_remotefname(host, args, fname)
		fname = complete_cmd(host, args, fname)
		fname.gsub!("~/", ((host.user == "root") ? "/root/" : "/home/#{host.user}/"))

		match = fname.scan(/~([^ \/]+)/)
		match.each {|m| m = m[0];
			fname.gsub!("~#{m}/", ((m == "root") ? "/root/" : "/home/#{m}/"))
		}

		return fname
	end

	def complete_cmd(host, args, str)
		str = str.to_s.dup

		match = str.scan(/(%ARG\d+%)/)
		match.each {|m| m = m[0]; str.gsub!(m, args[m[4..-2].to_i].to_s) }

		match = str.scan(/\(\(\$([^ ]+)/)
		match.each {|m| m = m[0];
			raise "unknown 'macro' #{m} in #{@parent.taskname}/#{subtaskname}" if $desc["macros"][m].nil?
			str.gsub!("(($#{m}", $desc["macros"][m].to_s)
		}

		return str
	end

	def verbose(msg)
		$stderr.puts msg if $gvars[:verbose]
	end
end

class KissItConnection < KissIt
	def exec(cmd, opts= {});		raise "prototype called";	end
	def cp(localfname, remotefname);	raise "prototype called";	end
end

class KissItConnectionSSH < KissItConnection
	def connect(host)
		@parent = host
		@ssh = Net::SSH.start(host.ip, host.user, password: host.password)
		return self
	end

	def disconnect()
		@ssh.close
		@ssh = nil
	end

	def exec(cmd, opts= nil)
		cmd = cmd.to_s.dup
		cmd = "sudo -u #{@parent.sudo} " + cmd if @parent.sudo
		ret = ""
		opts ||= {}
		status ||= {}

		$stderr.puts "     exec: #{cmd.inspect}"
		begin
			@ssh.exec!(cmd, status: status) do |channel, stream, data|
				if not data.empty?
					$stderr.print "     > " if ret.empty?
					$stderr.print "\n       " if (not ret.empty?) and data[-1] == "\n"
					$stderr.print data.rstrip.gsub("\n", "\n       ")
				end

				ret += data
			end
			$stderr.puts "#{"\n" if ret[-1] == "\n"}     # returned: #{status[:exit_code]}"

		rescue IOError => e
			if opts[:flags].include? :will_lose_connection
				$stderr.puts "       ### Connection lost - but was expected"
				return ["", 0] if opts[:ret_output].to_i == 1
				return 0
			else
				raise e
			end
		end

		($stderr.puts "!!!!!!!! FAILED: #{cmd} returned code:#{status[:exit_code]}"; exit 1) \
				if (not status[:exit_code].zero?) and opts[:error_is_ok].to_i == 0

		return [status[:exit_code], ret.to_s] if opts[:ret_output].to_i == 1
		return status[:exit_code]
	end

	def cp(localfname, remotefname)
		@ssh.scp.upload! localfname, remotefname
	end
end

# func
def usage(ex= nil)
	$stderr.puts "Usage: #{$0} [options] descfile <hostname or *> <task or *> <subtasks>"
	$stderr.puts "  subtasks default: #{$default_subtasks}"
	$stderr.puts "  -f, --force			force execution / ignore state"
	$stderr.puts "  -n, --no-verify			don't verify completion with state"
	$stderr.puts "  -V, --verbose			print additional debug output"
	$stderr.puts "      --debug-tasks		sets a break point at the beginning and end tasks"
	$stderr.puts "      --refmt			prints reformated yml to stdout and exits"
	$stderr.puts "  -?, --help			show this message"
	$stderr.puts "      --version			display version information"
	exit ex unless ex.nil?
end

def version()
	$stderr.puts "#{$0} version #{VERSION}"
	exit 0
end

def process_args()
	opts= GetoptLong.new(
		[ "--force",	"-f",	GetoptLong::NO_ARGUMENT ],
		[ "--no-verify", "-n",	GetoptLong::NO_ARGUMENT ],
		# since we have additional parameter, we can't use opt here
		[ "--verbose",	"-V",	GetoptLong::NO_ARGUMENT ],
		[ "--debug-tasks",	GetoptLong::NO_ARGUMENT ],
		[ "--refmt",		GetoptLong::NO_ARGUMENT ],
		[ "--help",	"-?",	GetoptLong::NO_ARGUMENT ],
		[ "--version",		GetoptLong::NO_ARGUMENT ],
	)

	begin
		opts.quiet = true

		opts.each do | opt, arg |
			case opt
			when "--force"
				$gvars[:force] = true
			when "--no-verify"
				$gvars[:verify] = false
			when "--verbose"
				$gvars[:verbose] = true
			when "--debug-tasks"
				$gvars[:debug_tasks] = true
			when "--refmt"
				$gvars[:refmt] = true
			when "--help"
				usage(0)
			when "--version"
				version()
			else
				raise "NYI"
			end
		end
	rescue
		raise "GetoptLong error: #{opts.error_message()}"
	end

	usage(1) if ARGV.length() < 1 or ARGV.length() > 4
	$gvars[:yml] = ARGV[0]
	$gvars[:hostname] = ARGV[1] || "*"
	$gvars[:taskname] = ARGV[2] || "*"
	$gvars[:subtasks] = (ARGV[3] || $default_subtasks).split(':')
end

def load_yml()
	base = {"include" => [], "hosts" => {}, "tasks" => {}, "macros" => {}}
	return base.merge(YAML.load_file($gvars[:yml]) || {})
end

def validate_yml(desc)
	# print reformated yaml file
	($stdout.puts YAML.dump(desc); exit 0) if $gvars[:refmt]

	desc["include"].each {|inc|
		data = YAML.load_file(inc)
		desc["hosts"].merge!(data["hosts"] || {})
		desc["tasks"].merge!(data["tasks"] || {})
		desc["macros"].merge!(data["macros"] || {})
	}

	desc["hosts"].each {|hostname, hostdesc|
		next if hostdesc.nil?
		desc["hosts"][hostname] = KissItHost.new.set(hostname, hostdesc)
	}

	desc["tasks"].each {|taskname, taskdesc|
		next if taskdesc.nil?
		desc["tasks"][taskname] = KissItTask.new.set(taskname, taskdesc)
	}

	return desc
end

def hndl_desc()
	if $gvars[:hostname] != "*"
		host = $desc["hosts"][$gvars[:hostname]]
		raise "hostname #{$gvars[:hostname]} not found" if host.nil?
		hndl_host(host)
	else
		$desc["hosts"].each {|name, host| hndl_host(host) }
	end
end

def hndl_host(host)
	$stderr.puts "## HOST: #{host.hostname}"

	host.connect()

	if $gvars[:taskname] != "*"
		hndl_task(host, $gvars[:taskname])
	else
		host.wants.to_a.each {|taskname|
			hndl_task(host, taskname[0], taskname[1..-1])
		}
	end

	host.disconnect()
end

def hndl_task(host, taskname, args = [])
	# execute task for each value in array
	args.each_with_index {|arg, i|
		if arg.class == Array
			arg.each {|a|
				a = [a] if a.class != Array
				hndl_task(host, taskname, (i.zero? ? [] : args[0..i-1]) + a + (args[i+1..-1] || []))
			}
			return
		end
	}

	raise "task #{taskname.inspect} wanted by #{host.hostname.inspect} unknown" if $desc["tasks"][taskname].nil?
	$desc["tasks"][taskname].exec(host, args)
end

# main
Pry.rescue do
	process_args()
	$desc = validate_yml(load_yml())
	hndl_desc()
end

# vim: syntax=ruby ts=8
