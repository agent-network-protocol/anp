package com.agentconnect.authentication;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.IDN;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** Public URL/connection policy. Resolver output is checked before numeric dialing. */
public final class PublicNetworkPolicy {
    public static final int MAX_BYTES = 1024 * 1024;
    private PublicNetworkPolicy() {}

    public static String origin(URI uri) {
        String scheme = uri.getScheme(), host = uri.getHost();
        String authority = uri.getRawAuthority();
        if (!("https".equals(scheme) || "http".equals(scheme)) || host == null || host.isEmpty()
                || authority == null || authority.contains("@") || uri.getRawFragment() != null
                || uri.toString().chars().anyMatch(c -> c <= 32 || c == 127 || c == '\\')
                || uri.getPort() == 0 || uri.getPort() > 65535) {
            throw new IllegalArgumentException("Invalid authentication URL");
        }
        host = host.toLowerCase(Locale.ROOT);
        if (host.startsWith("[")) host = "["+canonicalIPv6(host.substring(1,host.length()-1))+"]";
        else host = IDN.toASCII(host);
        int port = uri.getPort() < 0 ? (scheme.equals("https") ? 443 : 80) : uri.getPort();
        return scheme + "://" + host + ":" + port;
    }

    private static String canonicalIPv6(String literal) {
        if(literal.contains("%"))throw new IllegalArgumentException("Scoped IPv6 origin is not supported");
        final byte[] bytes;
        // A colon-containing URI-validated numeric literal cannot perform DNS.
        try {bytes=InetAddress.getByName(literal).getAddress();}
        catch(UnknownHostException invalid){throw new IllegalArgumentException("Invalid IPv6 origin");}
        if(bytes.length!=16)throw new IllegalArgumentException("Mapped IPv6 origin is not supported");
        int[] groups=new int[8];for(int index=0;index<8;index++)groups[index]=((bytes[index*2]&255)<<8)|(bytes[index*2+1]&255);
        int start=-1,length=1;
        for(int index=0;index<8;){if(groups[index]!=0){index++;continue;}int end=index;while(end<8&&groups[end]==0)end++;if(end-index>length){start=index;length=end-index;}index=end;}
        java.util.List<String> left=new java.util.ArrayList<>(),right=new java.util.ArrayList<>();
        for(int index=0;index<8;index++){if(start<0||index<start)left.add(Integer.toHexString(groups[index]));else if(index>=start+length)right.add(Integer.toHexString(groups[index]));}
        return start<0?String.join(":",left):String.join(":",left)+"::"+String.join(":",right);
    }

    private static String scopedPath(URI uri) {
        String path=uri.getPath()==null?"":uri.getPath();
        // Account for proxy/server decoding of dangerous path metacharacters;
        // keep ordinary encoded DID authority values (e.g. %3A) untouched.
        for(int depth=0;depth<4;depth++) {
            String decoded=path.replaceAll("(?i)%25","%")
                .replaceAll("(?i)%2e",".").replaceAll("(?i)%2f","/").replaceAll("(?i)%5c","/").replace('\\','/');
            if(decoded.equals(path))break;
            path=decoded;
        }
        if(java.util.regex.Pattern.compile("(?i)%(?:25|2e|2f|5c)").matcher(path).find())throw new SecurityException("Ambiguous trusted endpoint path");
        try {return new URI(null,null,path,null).normalize().getPath();}
        catch(java.net.URISyntaxException invalid){throw new SecurityException("Invalid trusted endpoint path");}
    }

    public static void validate(URI uri, URI trustedBase) {
        String origin = origin(uri);
        if (trustedBase != null) {
            String prefix = scopedPath(trustedBase).replaceAll("/+$", "");
            String path = scopedPath(uri);
            if (!origin(trustedBase).equals(origin) || trustedBase.getRawQuery() != null
                    || (!prefix.isEmpty() && !path.equals(prefix) && !path.startsWith(prefix + "/"))) {
                throw new SecurityException("Unapproved trusted endpoint scope");
            }
            return;
        }
        if (!uri.getScheme().equals("https")) throw new SecurityException("Public ANP requests require HTTPS");
        String host = uri.getHost().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        if (host.equals("localhost") || host.endsWith(".localhost")) throw new SecurityException("Non-public ANP destination");
        // HTTP libraries may bypass their DNS resolver for literals. Validate
        // those here, without ever resolving an arbitrary hostname during parsing.
        if (host.indexOf(':') >= 0) {
            if (host.indexOf('%') >= 0) throw new SecurityException("Scoped IP destination rejected");
            try {
                String literal = host.startsWith("[") ? host.substring(1, host.length() - 1) : host;
                if (!isPublic(InetAddress.getByName(literal))) throw new SecurityException("Non-public ANP destination");
            } catch (UnknownHostException invalid) { throw new SecurityException("Invalid IP destination"); }
        } else if (host.matches("[0-9.]+")) {
            String[] octets = host.split("\\.", -1);
            if (octets.length != 4) throw new SecurityException("Non-canonical IP destination");
            byte[] raw = new byte[4];
            for (int i = 0; i < 4; i++) {
                if (!octets[i].matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(octets[i]) > 255) throw new SecurityException("Invalid IP destination");
                raw[i] = (byte) Integer.parseInt(octets[i]);
            }
            try { if (!isPublic(InetAddress.getByAddress(raw))) throw new SecurityException("Non-public ANP destination"); }
            catch (UnknownHostException impossible) { throw new IllegalStateException(impossible); }
        }
    }

    public static boolean isPublic(InetAddress address) {
        byte[] raw = address.getAddress();
        if (raw.length == 16) {
            boolean mapped = true;
            for (int i = 0; i < 10; i++) mapped &= raw[i] == 0;
            if (mapped && raw[10] == (byte) 255 && raw[11] == (byte) 255) {
                byte[] v4 = java.util.Arrays.copyOfRange(raw, 12, 16);
                try { return isPublic(InetAddress.getByAddress(v4)); }
                catch (UnknownHostException impossible) { return false; }
            }
            int first = (raw[0] & 255) << 8 | raw[1] & 255;
            int second = (raw[2] & 255) << 8 | raw[3] & 255;
            return (first & 0xe000) == 0x2000 && !(first == 0x2001 && (second < 0x200 || second == 0xdb8))
                    && first != 0x2002 && (first & 0xfff0) != 0x3ff0;
        }
        if (raw.length != 4) return false;
        int a = raw[0] & 255, b = raw[1] & 255, c = raw[2] & 255;
        return !(a == 0 || a == 10 || a == 127 || a >= 224 || a == 100 && b >= 64 && b <= 127
                || a == 169 && b == 254 || a == 172 && b >= 16 && b <= 31
                || a == 192 && (b == 168 || b == 0 && (c == 0 || c == 2))
                || a == 198 && (b == 18 || b == 19 || b == 51 && c == 100) || a == 203 && b == 0 && c == 113);
    }

    /** Return the same checked numeric addresses. Never resolve a second time. */
    public static InetAddress[] checkAddresses(InetAddress[] addresses) throws UnknownHostException {
        if (addresses == null || addresses.length == 0) throw new UnknownHostException("ANP DNS returned no addresses");
        for (InetAddress address : addresses) if (!isPublic(address)) throw new UnknownHostException("ANP DNS resolved to a non-public address");
        return addresses.clone();
    }

    public static byte[] readBounded(InputStream input) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int count;
        while ((count = input.read(chunk)) >= 0) {
            if (bytes.size() + count > MAX_BYTES) throw new IOException("ANP response exceeds size limit");
            bytes.write(chunk, 0, count);
        }
        return bytes.toByteArray();
    }

    public static URI didResource(String did) {
        if (did == null || !did.startsWith("did:wba:")) throw new IllegalArgumentException("Unsupported DID method");
        String[] parts = did.split(":", -1);
        String authority = java.net.URLDecoder.decode(parts[2].replace("+", "%2B"), StandardCharsets.UTF_8);
        if (authority.isEmpty() || authority.matches(".*[/\\\\?#%@\\p{Cntrl} ].*")) throw new IllegalArgumentException("Invalid DID authority");
        URI base = URI.create("https://" + authority);
        origin(base);
        StringBuilder path = new StringBuilder();
        for (int i = 3; i < parts.length; i++) {
            String segment = java.net.URLDecoder.decode(parts[i].replace("+", "%2B"), StandardCharsets.UTF_8);
            if (segment.isEmpty() || segment.equals(".") || segment.equals("..") || segment.matches(".*[/\\\\?#%\\p{Cntrl}].*")) {
                throw new IllegalArgumentException("Unsafe DID path");
            }
            path.append('/').append(java.net.URLEncoder.encode(segment, StandardCharsets.UTF_8).replace("+", "%20"));
        }
        return URI.create(base + (path.length() == 0 ? "/.well-known/did.json" : path + "/did.json"));
    }
}
