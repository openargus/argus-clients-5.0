#!@PERLBIN@
# 
#  Gargoyle Client Software. Tools to read, analyze and manage Argus data.
#  Copyright (c) 2000-2017 QoSient, LLC
#  All rights reserved.
# 
#  THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
#  AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
#  EXPRESS PERMISSION OF QoSIENT, LLC.
# 
#  QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
#  SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
#  SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
#  IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
#  ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
#  THIS SOFTWARE.
#
#  
#   ra() based host use report
#  
#  $Id: //depot/gargoyle/clients/examples/rahosts/rahosts.pl#5 $
#  $DateTime: 2014/10/07 15:00:33 $
#  $Change: 2938 $
# 

#
# Complain about undeclared variables

use strict;

# Used modules
use POSIX;
use URI::URL;
use DBI;
use Switch;
use Net::IP;

use Socket;

# Global variables
my $debug = 0;
my $tmpfile = tmpnam();
my $tmpconf = $tmpfile . ".conf";

my $Program = `which ra`;
my $Options = "-L -1 -n -s sid:42 inf saddr:32 daddr:32 proto -c , ";
my $VERSION = "5.0";                

chomp $Program;

our ($mode, %items, %addrs, $sid, $inf, $saddr, $daddr, $taddr, $baddr, $proto, $stype);

my $quiet = 0;
my $done = 0;
my @args;

my ($sx, $sy, $sz, $sw);
my ($dx, $dy, $dz, $dw);

my $uri     = 0;
my $scheme;
my $netloc;
my $path;

my @arglist = ();

ARG: while (my $arg = shift(@ARGV)) {
   if (!$done) {
      for ($arg) {
         s/^-q//     && do { $quiet++; next ARG; };
         s/^-w//     && do { $uri = shift (@ARGV); next ARG; };
         s/^-debug// && do { $debug++; next ARG; };
      }

   } else {
      for ($arg) {
         s/\(/\\\(/            && do { ; };
         s/\)/\\\)/            && do { ; };
      }
   }
   $arglist[@arglist + 0] = $arg;
}

# Start the program

my $etherRegex = '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$';
my $ipv4Regex  = '\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b';
my $ipv6Regex  = '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))';

chomp $Program;
my @args = ($Program, $Options, @arglist);

print "DEBUG: calling @args\n" if $debug;
open(SESAME, "@args |");

while (my $data = <SESAME>) {
   chomp $data;
   ($sid, $inf, $saddr, $daddr, $proto) = split (/,/, $data);

   if (!($proto eq "man")) {
      if ($saddr =~ /$etherRegex/) {
         $stype = "ether";
      } else {
      if ($saddr =~ /$ipv4Regex/) {
         $stype = "ipv4";
      } else {
      if ($saddr =~ /$ipv6Regex/) {
         $stype = "ipv6";
      } else {
      if ($saddr =~ /:/) {
         $stype = "ether";
      }}}}

      print "DEBUG: address type: $stype\n" if $debug;

      switch ($stype) {
         case "ipv4"  { 
            if ((!($saddr eq "0.0.0.0")) && (!($daddr eq "0.0.0.0"))) {
               $addrs{$stype}{$sid}{$inf}{$saddr}++;
               $items{$stype}{$sid}{$inf}{$saddr}{$daddr}++;
               $addrs{$stype}{$sid}{$inf}{$daddr}++;
               $items{$stype}{$sid}{$inf}{$daddr}{$saddr}++;
            }
         }
         case "ether" { next }
         case "ipv6"  {
            $addrs{$stype}{$sid}{$inf}{$saddr}++;
            $items{$stype}{$sid}{$inf}{$saddr}{$daddr}++;
            $addrs{$stype}{$sid}{$inf}{$daddr}++;
            $items{$stype}{$sid}{$inf}{$daddr}{$saddr}++;
         }
      }
   }
}
close(SESAME);


my $startseries = 0;
my $startcount = 0;
my $lastseries = 0;
my $lastcount = 0;
my $count = 0;

my ($user, $pass, $host, $port, $space, $db, $table);
my $dbh;

if ($uri) {
   my $url = URI::URL->new($uri);

   $scheme = $url->scheme;
   $netloc = $url->netloc;
   $path   = $url->path;

   if ($netloc ne "") {
      ($user, $host) = split /@/, $netloc;
      if ($user =~ m/:/) {
         ($user , $pass) = split/:/, $user;
      }
      if ($host =~ m/:/) {
         ($host , $port) = split/:/, $host;
      }
   }
   if ($path ne "") {
      ($space, $db, $table)  = split /\//, $path;
   }

   $dbh = DBI->connect("DBI:$scheme:$db", $user, $pass) || die "Could not connect to database: $DBI::errstr";

   # Drop table 'foo'. This may fail, if 'foo' doesn't exist
   # Thus we put an eval around it.

   {
      local $dbh->{RaiseError} = 0;
      local $dbh->{PrintError} = 0;

      eval { $dbh->do("DROP TABLE $table") };
   }

   # Create a new table 'foo'. This must not fail, thus we don't catch errors.

   $dbh->do("CREATE TABLE $table (sid VARCHAR(64), inf VARCHAR(4), addr VARCHAR(64) NOT NULL, count INTEGER, hoststring TEXT, PRIMARY KEY ( addr,sid,inf ))");

   for $stype ( sort keys(%items) ) {
      for $sid ( sort keys(%{$items{$stype}}) ) {
         for $inf ( sort keys( $items{$stype}{$sid}) ) {
            for $saddr ( sort internet keys( $items{$stype}{$sid}{$inf}) ) {
               my $hoststring = "";
               $startseries = 0;
               $lastseries = 0;

               if ($addrs{$stype}{$sid}{$inf}{$saddr} >= 1) {
                  if ( scalar(keys(%{$items{$stype}{$sid}{$inf}{$saddr} })) > 0 ) {
                     $count = RaGetAddressCount($saddr, $stype, $sid, $inf);

                     if ( $quiet == 0 ) {
                        switch ($stype) {
                           case "ipv4"  { 
                              for $sx ( sort numerically keys(%{$items{$stype}{$sid}{$inf}{$saddr} })) {
                                 if ( scalar(keys(%{$items{$stype}{$sid}{$inf}{$saddr}{$sx} })) > 0 ) {
                                    for $sy ( sort numerically keys(%{$items{$stype}{$sid}{$inf}{$saddr}{$sx}})) {
                                       if ( scalar(keys(%{$items{$stype}{$sid}{$inf}{$saddr}{$sx}{$sy}})) > 0 ) {
                                          for $sz ( sort numerically keys(%{$items{$stype}{$sid}{$inf}{$saddr}{$sx}{$sy}})) {
                                             if ( scalar(keys(%{$items{$stype}{$sid}{$inf}{$saddr}{$sx}{$sy}{$sz}})) > 0 ) {
                                                for $sw ( sort numerically keys(%{$items{$stype}{$sid}{$inf}{$saddr}{$sx}{$sy}{$sz}})) {
                                                   my $addr = "$sx.$sy.$sz.$sw";
                                                   my $ipaddr = inet_aton($addr);
                                                   my $naddr = unpack "N", $ipaddr;

                                                   if ($startseries > 0) {
                                                      if ($naddr == ($lastseries + 1)) {
                                                         $lastseries = $naddr;  
                                                         $lastcount = $items{$stype}{$sid}{$inf}{$saddr}{$sx}{$sy}{$sz}{$sw};  
                                                      } else {
                                                         my ($a1, $a2, $a3, $a4) = unpack('C4', pack("N", $lastseries));
                                                         if ((($a4 == 254) && ($sw == 0)) && (($a3 + 1) == $sz)) {
                                                            $lastseries = $naddr;
                                                            $lastcount = $items{$stype}{$sid}{$inf}{$saddr}{$sx}{$sy}{$sz}{$sw};  
                                                         } else {
                                                            my $startaddr = inet_ntoa(pack "N", $startseries);
                                                            my $lastaddr  = inet_ntoa(pack "N", $lastseries);

                                                            if ($startseries != $lastseries) {
                                                               $hoststring .= "$startaddr($startcount)-$lastaddr($lastcount),";
                                                               $startseries = $naddr;
                                                               $startcount = $items{$stype}{$sid}{$inf}{$saddr}{$sx}{$sy}{$sz}{$sw};  
                                                               $lastseries = $naddr;
                                                               $lastcount = $items{$stype}{$sid}{$inf}{$saddr}{$sx}{$sy}{$sz}{$sw};  
                                                            } else {
                                                               $hoststring .= "$startaddr($startcount),";
                                                               $startseries = $naddr;
                                                               $startcount = $items{$stype}{$sid}{$inf}{$saddr}{$sx}{$sy}{$sz}{$sw};  
                                                               $lastseries = $naddr;
                                                               $lastcount = $items{$stype}{$sid}{$inf}{$saddr}{$sx}{$sy}{$sz}{$sw};  
                                                            }
                                                         }
                                                      }

                                                   } else {
                                                      $startseries = $naddr;
                                                      $startcount = $items{$stype}{$sid}{$inf}{$saddr}{$sx}{$sy}{$sz}{$sw};  
                                                      $lastseries = $naddr;
                                                      $lastcount = $items{$stype}{$sid}{$inf}{$saddr}{$sx}{$sy}{$sz}{$sw};  
                                                   }
                                                }
                                             }
                                          }
                                       }
                                    }
                                 }
                              }
                           }
                        }
                     }
                   
                     if ($startseries > 0) {
                        my $startaddr = inet_ntoa(pack "N", $startseries);
                        my $lastaddr  = inet_ntoa(pack "N", $lastseries);

                        if ($startseries != $lastseries) {
                           $hoststring .= "$startaddr($startcount)-$lastaddr($lastcount)";
                        } else {
                           $hoststring .= "$startaddr($startcount)";
                        }
                     }
                  }

                  if (length ($hoststring)) {
                     $dbh->do("INSERT INTO $table VALUES(?, ?, ?, ?, ?)", undef, $sid, $inf, $saddr, $count, $hoststring);
                  }
               }
            }
         }
      }
   }

   $dbh->disconnect();

} else {
   for $stype ( sort keys(%items) ) {
      switch ($stype) {
         case "ether" { next }
         case "ipv6"  {
            for $sid ( sort keys(%{$items{$stype}}) ) {
               for $inf ( sort keys( %{$items{$stype}{$sid}}) ) {
                  for $saddr ( sort internet keys( %{$items{$stype}{$sid}{$inf}}) ) {
                     my $cnt = 0;

                     $count = RaGetAddressCount($saddr, $stype, $sid, $inf);
                     print "$sid:$inf $saddr: ($count) ";
                     for $daddr ( sort internet keys( %{$items{$stype}{$sid}{$inf}{$saddr}}) ) {
                        if ($cnt++ > 0) {
                           print ",";
                        }
                        print "$daddr";
                     }
                     print "\n";
                  }
               }
            }
         }

         case "ipv4"  {
            for $sid ( sort keys(%{$items{$stype}}) ) {
               for $inf ( sort keys( %{$items{$stype}{$sid}}) ) {
                  for $saddr ( sort internet keys( %{$items{$stype}{$sid}{$inf}}) ) {
                     $startseries = 0;
                     $lastseries = 0;
                     $count = RaGetAddressCount($saddr, $stype, $sid, $inf);
                     print "$sid:$inf $saddr: ($count) ";

                     if ( $quiet == 0 ) {
                        for $daddr ( sort internet keys(%{$items{$stype}{$sid}{$inf}{$saddr} })) {
                           my $ipaddr = inet_aton($daddr);
                           my $naddr = unpack "N", $ipaddr;
                           if ($startseries > 0) {
                              if ($naddr == ($lastseries + 1)) {
                                 $lastseries = $naddr;  
                                 $lastcount = $items{$stype}{$sid}{$inf}{$saddr}{$daddr};
                              } else {
                                 my ($a1, $a2, $a3, $a4) = unpack('C4', pack("N", $lastseries));
                                 if ((($a4 == 254) && ($sw == 0)) && (($a3 + 1) == $sz)) {
                                    $lastseries = $naddr;
                                    $lastcount = $items{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                 } else {
                                    my $startaddr = inet_ntoa(pack "N", $startseries);
                                    my $lastaddr  = inet_ntoa(pack "N", $lastseries);

                                    if ($startseries != $lastseries) {
                                       print "$startaddr($startcount)-$lastaddr($lastcount),";
                                       $startseries = $naddr;
                                       $startcount = $items{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                       $lastseries = $naddr;
                                       $lastcount = $items{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                    } else {
                                       print "$startaddr($startcount),";
                                       $startseries = $naddr;
                                       $startcount = $items{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                       $lastseries = $naddr;
                                       $lastcount = $items{$stype}{$sid}{$inf}{$saddr}{$daddr};
                                    }
                                 }
                              }
                           } else {
                              $startseries = $naddr;
                              $startcount = $items{$stype}{$sid}{$inf}{$saddr}{$daddr};
                              $lastseries = $naddr;
                              $lastcount = $items{$stype}{$sid}{$inf}{$saddr}{$daddr};
                           }
                        }
                     }
                   
                     if ($startseries > 0) {
                        my $startaddr = inet_ntoa(pack "N", $startseries);
                        my $lastaddr  = inet_ntoa(pack "N", $lastseries);

                        if ($startseries != $lastseries) {
                           print "$startaddr($startcount)-$lastaddr($lastcount)";
                        } else {
                           print "$startaddr($startcount)";
                        }
                     }
                     print "\n";
                  }
               }
            }
         }
      }
   }
}

`rm -f $tmpconf`;
exit 0;


sub RaGetAddressCount() {
   my $thisaddr = shift(@_);
   my $thistype = shift(@_);
   my $sid = shift(@_);
   my $inf = shift(@_);
   my $retn = 0;
   my $daddr;

   for $daddr ( keys( %{$items{$thistype}{$sid}{$inf}{$thisaddr}} )) {
      $retn++;
   }

   return ($retn);
}

sub numerically { $a <=> $b };

sub internet {
   my $ipA = new Net::IP ($a);
   my $ipB = new Net::IP ($b);
   return ($ipA->intip() <=> $ipB->intip()); 
}
