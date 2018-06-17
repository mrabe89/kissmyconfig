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
$gvars = {verbose: false, force: false, verify: true, record: false, debug_tasks: false, refmt: false}
$desc = nil
$default_subtasks = "prep:install:config"

# class
class KissIt
end

class KissItHost < KissIt
	def hostname;	return @cfg[:hostname];	end
	def ip;		return @cfg[:ip];	end
	def password;	return @cfg[:password];	end
	def user;	return @cfg[:user];	end
	def sudo;	return @cfg[:sudo];	end
	def wants;	return @wants;		end

	def set(hostname, hostdesc)
		@cfg = {hostname: hostname, ip: nil, password: nil, user: nil, sudo: nil}
		@wants = []
		@connection = nil

		raise "#{hostname} ip missing or not a string" if hostdesc["ip"].class != String

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

	def exec(t, cmd, opts= {})
		connect() if not @connection
		@connection.exec(t, cmd, opts)
	end

	def cp(localfname, remotefname)
		connect() if not @connection
		@connection.cp(localfname, remotefname)
	end

	def connect()
		@connection = KissItConnectionSSH.new.connect(@cfg[:ip], @cfg[:user], password: @cfg[:password])
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
			@subs[subtaskname.to_sym] = KissItTaskSub.new.set(subtaskname, subtaskdesc)
		}

		return self
	end

	def exec(hostname, hostdesc, taskname, args = [])
		t = {task: $desc["tasks"][taskname], taskname: taskname, args: args, host: hostdesc, hostname: hostname}

		binding.pry if $gvars[:debug_tasks]

		if t[:task].nil? and not $gvars[:record]
			return if $desc["tasks"].include?(taskname)
			raise "task #{t[:taskname].inspect} wanted by #{t[:hostname].inspect} unknown"
		end

		if $gvars[:record]
			t[:task] = {}
			$gvars[:subtasks].each {|subtask| t[:task][subtask] = {"pre" => [], "post" => []}}
		end

		$gvars[:subtasks].each {|subtask| t[:subtask] = subtask
			next if t[:task][subtask].nil? and not $gvars[:record]

			$stderr.puts " ### DO #{t[:taskname]}/#{t[:subtask]}"

			(hndl_task_record(t); next) if $gvars[:record]

			next if hndl_task_state_ck(t) == :skip

			hndl_task_exec(t, "pre")
			hndl_task_upload(t)
			hndl_task_exec(t, "post")

			hndl_task_state_ck(t, false)

			if t[:task][t[:subtask]]["flags"]
				($stderr.puts "   ### sleep 10"; sleep 10) if t[:task][t[:subtask]]["flags"].include? :sleep_10
				($stderr.puts "   ### sleep 30"; sleep 30) if t[:task][t[:subtask]]["flags"].include? :sleep_30
				($stderr.puts "   ### sleep 60"; sleep 60) if t[:task][t[:subtask]]["flags"].include? :sleep_60
			end

			$stderr.puts  "   ### OK"
		}
		$stderr.puts  " ### OK"

		if $gvars[:record]
			dump = YAML.dump({"tasks" => {t[:taskname] => t[:task]}})
			if $gvars[:record_fname]
				File.open($gvars[:record_fname], "a") {|f| f.puts dump}
				$stderr.puts "## Record saved to #{$gvars[:record_fname]}"
			else
				$stderr.puts dump
			end
		end

		binding.pry if $gvars[:debug_tasks]
	end

	def hndl_task_record(t)
		$stderr.puts "   ### Check State"
		$stderr.puts "     ### Recording started (end with ctrl+d)"
		while line = Readline.readline('> ', true)
			ret = t[:host].exec(t, line, {error_is_ok: 1})
			t[:task][t[:subtask]]["state"] = line
		end

		$stderr.puts "\n   ### Exec Pre"
		$stderr.puts "     ### Recording started (end with ctrl+d)"
		while line = Readline.readline('> ', true)
			ret = t[:host].exec(t, line, {error_is_ok: 1})
			if ret.zero?
				t[:task][t[:subtask]]["pre"] << line
			else
				$stderr.puts "cmd returned with error / not saved"
			end
		end

		hndl_task_state_ck(t, false)
	end

	def hndl_task_state_ck(t, preck= true)
		return :ok if (preck and $gvars[:force]) or (not preck and not $gvars[:verify])
		return :ok if not t[:task][t[:subtask]]["state"] and not t[:task][t[:subtask]]["cp"]

		$stderr.puts  "   ### Check #{preck ? "State" : "Success"}"
		ret = 0

		if t[:task][t[:subtask]]["state"]
			t[:task][t[:subtask]]["state"].each {|cmd|
				ret = t[:host].exec(t, complete_cmd(t, cmd), {error_is_ok: 1})
				break if not ret.zero?
			}
		end

		if t[:task][t[:subtask]]["cp"] and ret == 0
			t[:task][t[:subtask]]["cp"].each {|localfname, remotedesc|
				md5_local = `md5sum '#{get_localfname(t, localfname)}'`
				ret, md5_remote = t[:host].exec(t, "md5sum '#{get_remotefname(t, remotedesc[0])}'", {error_is_ok: 1, ret_output: 1});
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

	def hndl_task_exec(t, subsubtask)
		if t[:task][t[:subtask]][subsubtask]
			$stderr.puts "   ### Perform Actions (#{subsubtask})"
			t[:task][t[:subtask]][subsubtask].each {|cmd| t[:host].exec(t, complete_cmd(t, cmd)) }
		end
	end

	def hndl_task_upload(t)
		if t[:task][t[:subtask]]["cp"]
			$stderr.puts "   ### Uploading Files"

			t[:task][t[:subtask]]["cp"].each {|localfname, remotedesc|
				localfname = get_localfname(t, localfname)
				remotefname = get_remotefname(t, remotedesc[0])

				if t[:host].sudo
					tmp_fname="/tmp/kms_#{rand(36**8).to_s(36)}"
					$stderr.puts "     ### Upload: #{localfname} to #{tmp_fname}"
					t[:host].cp(localfname, tmp_fname)
					$stderr.puts "     ### Renaming to #{remotefname}"
					t[:host].exec(t, "mv #{tmp_fname} '#{remotefname}'")
				else
					$stderr.puts "     ### Upload: #{localfname} to #{remotefname}"
					t[:host].cp(localfname, remotefname)
				end

				if remotedesc[1]
					if remotedesc[1] != "@"
						t[:host].exec(t, "chown #{complete_cmd(t, remotedesc[1])} '#{remotefname}'")
					else
						t[:host].exec(t, "chown #{t[:host].user} '#{remotefname}'")
					end
				end
				t[:host].exec(t, "chmod #{complete_cmd(t, remotedesc[2])} '#{remotefname}'") if remotedesc[2]
			}
		end
	end

	def get_localfname(t, fname)
		fname = complete_cmd(t, fname)

		return "#{t[:host].hostname}/#{fname}" if File.exist?("#{t[:hostname]}/#{fname}")
		return fname if File.exist?(fname)

		raise "local file '#{fname}' not found"
	end

	def get_remotefname(t, fname)
		fname = complete_cmd(t, fname)
		fname.gsub!("~/", (((t[:host].user || "root") == "root") ? "/root/" : "/home/#{t[:host].user}/"))

		match = fname.scan(/~([^ \/]+)/)
		match.each {|m| m = m[0];
			fname.gsub!("~#{m}/", ((m == "root") ? "/root/" : "/home/#{m}/"))
		}

		return fname
	end

	def complete_cmd(t, str)
		str = str.to_s.dup

		match = str.scan(/(%ARG\d+%)/)
		match.each {|m| m = m[0]; str.gsub!(m, t[:args][m[4..-2].to_i].to_s) }

		match = str.scan(/\(\(\$([^ ]+)/)
		match.each {|m| m = m[0];
			raise "unknown 'macro' #{m} in #{t[:taskname]}/#{t[:subtask]}" if $desc["macros"][m].nil?
			str.gsub!("(($#{m}", $desc["macros"][m].to_s)
		}

		return str
	end

	def verbose(msg)
		$stderr.puts msg if $gvars[:verbose]
	end

end

class KissItTaskSub < KissIt
	def subtaskname;	return @cfg[:subtaskname];	end

	def set(subtaskname, subtaskdesc)
		@cfg = {subtaskname: subtaskname}
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
end

class KissItConnection < KissIt
	def exec(t, cmd, opts= {});		raise "prototype called";	end
	def cp(localfname, remotefname);	raise "prototype called";	end
end

class KissItConnectionSSH < KissItConnection
	def connect(ip, user = "root", password = nil)
		@ssh = Net::SSH.start(ip, user, password: password)
		return self
	end

	def disconnect()
		@ssh.close
		@ssh = nil
	end

	def exec(t, cmd, opts= {})
		cmd = cmd.to_s.dup
		cmd = "sudo -u #{t[:host].sudo} " + cmd if t[:host].sudo
		ret = ""
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
			if t[:task][t[:subtask]]["flags"] and t[:task][t[:subtask]]["flags"].include? :will_lose_connection
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
	$stderr.puts "  -r, --record			use a very crude readline shell to record a task"
	$stderr.puts "      --record-file	<fname>	same as record, but appends to file"
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
		[ "--record",	"-r",	GetoptLong::NO_ARGUMENT ],
		# since we have additional parameter, we can't use opt here
		[ "--record-file",	GetoptLong::REQUIRED_ARGUMENT ],
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
			when "--record", "--record-file"
				$gvars[:verbose] = true
				$gvars[:record] = true
				$gvars[:record_fname] = (arg.to_s.empty? ? nil : arg)
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

	desc["tasks_"] = {}
	desc["tasks"].each {|taskname, taskdesc|
		next if taskdesc.nil?
		desc["tasks_"][taskname] = KissItTask.new.set(taskname, taskdesc)

		taskdesc.each {|subtaskname, subtaskdesc|
			raise "subtaskname #{subtaskname} not allowed (in #{taskname})" \
					if not $gvars[:subtasks].include? subtaskname
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

				subtaskdesc[subsubtaskname] = subsubtaskdesc
			}
			taskdesc[subtaskname] = subtaskdesc
		}

		desc["tasks"][taskname] = taskdesc
	}

	return desc
end

def hndl_desc()
	if $gvars[:hostname] != "*"
		host = $desc["hosts"][$gvars[:hostname]]
		raise "hostname #{$gvars[:hostname]} not found" if host.nil?
		hndl_host($gvars[:hostname], host)
	else
		$desc["hosts"].each {|name, desc| hndl_host(name, desc) }
	end
end

def hndl_host(name, host)
	$stderr.puts "## HOST: #{name}"

	host.connect()

	if $gvars[:taskname] != "*"
		hndl_task(name, host, $gvars[:taskname])
	else
		host.wants.to_a.each {|taskname|
			hndl_task(name, host, taskname[0], taskname[1..-1])
		}
	end

	host.disconnect()
end

def hndl_task(hostname, hostdesc, taskname, args = [])
	# execute task for each value in array
	args.each_with_index {|arg, i|
		if arg.class == Array
			arg.each {|a|
				a = [a] if a.class != Array
				hndl_task(hostname, hostdesc, taskname, (i.zero? ? [] : args[0..i-1]) + a + (args[i+1..-1] || []))
			}
			return
		end
	}

	$desc["tasks_"][taskname].exec(hostname, hostdesc, taskname, args)
end

# main
Pry.rescue do
	process_args()
	$desc = validate_yml(load_yml())
	hndl_desc()
end

# vim: syntax=ruby ts=8
