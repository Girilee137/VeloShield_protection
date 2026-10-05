package com.veloshield.security;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Set;

public class SsrfValidator {

    private static final Set<String> BLOCKED_HOSTS = Set.of(
            "localhost",
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "metadata.google.internal",
            "169.254.169.254"
    );

    public static class ValidationResult {
        private final boolean valid;
        private final String message;

        public ValidationResult(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }

        public boolean isValid() { return valid; }
        public String getMessage() { return message; }
    }

    /**
     * Validates that a URL is safe to request:
     * - Only HTTP and HTTPS
     * - Disallows private, loopback, multicast, link-local, and cloud metadata addresses
     */
    public static ValidationResult validateUrl(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            return new ValidationResult(false, "URL cannot be empty");
        }

        URI uri;
        try {
            uri = URI.create(urlString.trim());
        } catch (Exception e) {
            return new ValidationResult(false, "Invalid URL format: " + e.getMessage());
        }

        String scheme = uri.getScheme();
        if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
            return new ValidationResult(false, "Only http:// and https:// URLs are supported");
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            return new ValidationResult(false, "URL host cannot be empty");
        }

        String lowerHost = host.toLowerCase().trim();
        if (BLOCKED_HOSTS.contains(lowerHost) || lowerHost.endsWith(".localhost") || lowerHost.endsWith(".local") || lowerHost.endsWith(".internal")) {
            return new ValidationResult(false, "Requests to internal or local hosts are not allowed");
        }

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            if (addresses == null || addresses.length == 0) {
                return new ValidationResult(false, "Could not resolve host: " + host);
            }

            for (InetAddress addr : addresses) {
                if (isBlockedAddress(addr)) {
                    return new ValidationResult(false, "Host resolves to a restricted/private network address");
                }
            }
        } catch (UnknownHostException e) {
            return new ValidationResult(false, "Host name resolution failed: " + host);
        } catch (Exception e) {
            return new ValidationResult(false, "Security validation error: " + e.getMessage());
        }

        return new ValidationResult(true, "URL is valid");
    }

    private static boolean isBlockedAddress(InetAddress addr) {
        if (addr.isAnyLocalAddress() || addr.isLoopbackAddress() || addr.isLinkLocalAddress()) {
            return true;
        }
        if (addr.isSiteLocalAddress()) {
            return true;
        }
        if (addr.isMulticastAddress()) {
            return true;
        }

        byte[] bytes = addr.getAddress();
        if (bytes.length == 4) {
            int b0 = bytes[0] & 0xFF;
            int b1 = bytes[1] & 0xFF;

            // 10.0.0.0/8
            if (b0 == 10) return true;
            // 172.16.0.0/12
            if (b0 == 172 && (b1 >= 16 && b1 <= 31)) return true;
            // 192.168.0.0/16
            if (b0 == 192 && b1 == 168) return true;
            // 169.254.0.0/16 (link-local, cloud metadata)
            if (b0 == 169 && b1 == 254) return true;
            // 127.0.0.0/8
            if (b0 == 127) return true;
            // 0.0.0.0/8
            if (b0 == 0) return true;
        } else if (bytes.length == 16) {
            // IPv6 Unique Local Address (fc00::/7)
            if ((bytes[0] & 0xFE) == 0xFC) return true;
        }

        return false;
    }
}
