/*
 * Copyright (c) 2023-2025, Tim Flynn <trflynn89@ladybird.org>
 * Copyright (c) 2023, Cameron Youell <cameronyouell@gmail.com>
 * Copyright (c) 2025, Manuel Zahariev <manuel@duck.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/IPv4Address.h>
#include <AK/IPv6Address.h>
#include <AK/String.h>
#include <LibFileSystem/FileSystem.h>
#include <LibURL/Host.h>
#include <LibURL/Parser.h>
#include <LibURL/PublicSuffixData.h>
#include <LibWebView/URL.h>

namespace WebView {

static bool is_ipv4_private_or_loopback(u8 first, u8 second)
{
    // 127.0.0.0/8 (loopback)
    if (first == 127)
        return true;
    // 10.0.0.0/8 (private)
    if (first == 10)
        return true;
    // 172.16.0.0/12 (private)
    if (first == 172 && second >= 16 && second <= 31)
        return true;
    // 192.168.0.0/16 (private)
    if (first == 192 && second == 168)
        return true;
    // 169.254.0.0/16 (link-local)
    if (first == 169 && second == 254)
        return true;
    return false;
}

static bool is_host_private_or_loopback(URL::Host const& host)
{
    if (host.has<IPv4Address>()) {
        // Use host.serialize() to get the canonical dotted-decimal form,
        // then parse it back. This avoids byte-order issues with the internal
        // IPv4Address representation used by the URL parser.
        if (auto parsed = IPv4Address::from_string(host.serialize()); parsed.has_value())
            return is_ipv4_private_or_loopback((*parsed)[0], (*parsed)[1]);
        return false;
    }

    if (host.has<IPv6Address>()) {
        auto const& ipv6 = host.get<IPv6Address>();

        // ::1 (loopback)
        if (ipv6[0] == 0 && ipv6[1] == 0 && ipv6[2] == 0 && ipv6[3] == 0
            && ipv6[4] == 0 && ipv6[5] == 0 && ipv6[6] == 0 && ipv6[7] == 1)
            return true;

        return false;
    }

    // The URL parser may store IP addresses as domain strings.
    if (host.has<String>()) {
        if (auto parsed = IPv4Address::from_string(host.get<String>()); parsed.has_value())
            return is_ipv4_private_or_loopback((*parsed)[0], (*parsed)[1]);
    }

    return false;
}

Optional<URL::URL> sanitize_url(StringView location, Optional<SearchEngine> const& search_engine, AppendTLD append_tld)
{
    auto search_url_or_error = [&]() -> Optional<URL::URL> {
        if (!search_engine.has_value())
            return {};

        return URL::Parser::basic_parse(search_engine->format_search_query_for_navigation(location));
    };

    location = location.trim_whitespace();

    if (FileSystem::exists(location)) {
        auto path = FileSystem::real_path(location);
        if (!path.is_error())
            return URL::create_with_file_scheme(path.value());
        return search_url_or_error();
    }

    bool https_scheme_was_guessed = false;

    auto url = URL::create_with_url_or_path(location);

    if (!url.has_value() || url->scheme() == "localhost"sv) {
        url = URL::create_with_url_or_path(ByteString::formatted("https://{}", location));
        if (!url.has_value())
            return search_url_or_error();

        https_scheme_was_guessed = true;
    }

    // For private/loopback IP addresses, use http:// instead of https:// since
    // these addresses typically don't have TLS certificates.
    if (https_scheme_was_guessed) {
        if (auto const& host = url->host(); host.has_value() && is_host_private_or_loopback(*host)) {
            url = URL::create_with_url_or_path(ByteString::formatted("http://{}", location));
            if (!url.has_value())
                return search_url_or_error();
        }
    }

    // FIXME: Add support for other schemes, e.g. "mailto:". Firefox and Chrome open mailto: locations.
    static constexpr Array SUPPORTED_SCHEMES { "about"sv, "data"sv, "file"sv, "http"sv, "https"sv, "resource"sv };
    if (!any_of(SUPPORTED_SCHEMES, [&](StringView const& scheme) { return scheme == url->scheme(); }))
        return search_url_or_error();

    if (auto const& host = url->host(); host.has_value() && host->is_domain()) {
        auto const& domain = host->get<String>();

        if (domain.contains('"'))
            return search_url_or_error();

        // https://datatracker.ietf.org/doc/html/rfc2606
        static constexpr Array RESERVED_TLDS { ".test"sv, ".example"sv, ".invalid"sv, ".localhost"sv };
        if (any_of(RESERVED_TLDS, [&](StringView const& tld) { return domain.byte_count() > tld.length() && domain.ends_with_bytes(tld); }))
            return url;

        auto public_suffix = URL::PublicSuffixData::the()->get_public_suffix(domain);
        if (!public_suffix.has_value() || *public_suffix == domain) {
            if (append_tld == AppendTLD::Yes)
                url->set_host(MUST(String::formatted("{}.com", domain)));
            else if (https_scheme_was_guessed && domain != "localhost"sv)
                return search_url_or_error();
        }
    }

    return url;
}

Vector<URL::URL> sanitize_urls(ReadonlySpan<ByteString> raw_urls, URL::URL const& new_tab_page_url)
{
    Vector<URL::URL> sanitized_urls;
    sanitized_urls.ensure_capacity(raw_urls.size());

    for (auto const& raw_url : raw_urls) {
        if (auto url = sanitize_url(raw_url); url.has_value())
            sanitized_urls.unchecked_append(url.release_value());
    }

    if (sanitized_urls.is_empty())
        sanitized_urls.append(new_tab_page_url);

    return sanitized_urls;
}

static URLParts break_internal_url_into_parts(URL::URL const& url, StringView url_string)
{
    auto scheme = url_string.substring_view(0, url.scheme().bytes_as_string_view().length() + ":"sv.length());
    auto path = url_string.substring_view(scheme.length());

    return URLParts { scheme, path, {} };
}

static URLParts break_file_url_into_parts(URL::URL const& url, StringView url_string)
{
    auto scheme = url_string.substring_view(0, url.scheme().bytes_as_string_view().length() + "://"sv.length());
    auto path = url_string.substring_view(scheme.length());

    return URLParts { scheme, path, {} };
}

static URLParts break_web_url_into_parts(URL::URL const& url, StringView url_string)
{
    auto scheme = url_string.substring_view(0, url.scheme().bytes_as_string_view().length() + "://"sv.length());
    auto url_without_scheme = url_string.substring_view(scheme.length());

    StringView domain;
    StringView remainder;

    if (auto index = url_without_scheme.find_any_of("/?#"sv); index.has_value()) {
        domain = url_without_scheme.substring_view(0, *index);
        remainder = url_without_scheme.substring_view(*index);
    } else {
        domain = url_without_scheme;
    }

    auto public_suffix = URL::PublicSuffixData::the()->get_public_suffix(domain);
    if (!public_suffix.has_value() || !domain.ends_with(*public_suffix))
        return { scheme, domain, remainder };

    auto subdomain = domain.substring_view(0, domain.length() - public_suffix->bytes_as_string_view().length());
    subdomain = subdomain.trim("."sv, TrimMode::Right);

    if (auto index = subdomain.find_last('.'); index.has_value()) {
        subdomain = subdomain.substring_view(0, *index + 1);
        domain = domain.substring_view(subdomain.length());
    } else {
        subdomain = {};
    }

    auto scheme_and_subdomain = url_string.substring_view(0, scheme.length() + subdomain.length());
    return { scheme_and_subdomain, domain, remainder };
}

Optional<URLParts> break_url_into_parts(StringView url_string)
{
    auto maybe_url = URL::create_with_url_or_path(url_string);
    if (!maybe_url.has_value())
        return {};
    auto const& url = maybe_url.value();

    auto const& scheme = url.scheme();
    auto scheme_length = scheme.bytes_as_string_view().length();

    if (!url_string.starts_with(scheme))
        return {};

    auto schemeless_url = url_string.substring_view(scheme_length);

    if (schemeless_url.starts_with("://"sv)) {
        if (url.scheme() == "file"sv)
            return break_file_url_into_parts(url, url_string);
        if (url.scheme().is_one_of("http"sv, "https"sv))
            return break_web_url_into_parts(url, url_string);
    } else if (schemeless_url.starts_with(':')) {
        if (url.scheme().is_one_of("about"sv, "data"sv))
            return break_internal_url_into_parts(url, url_string);
    }

    return {};
}

URLType url_type(URL::URL const& url)
{
    if (url.scheme() == "mailto"sv)
        return URLType::Email;
    if (url.scheme() == "tel"sv)
        return URLType::Telephone;
    return URLType::Other;
}

ByteString url_text_to_copy(URL::URL const& url)
{
    auto url_text = url.to_byte_string();

    if (url.scheme() == "mailto"sv)
        return url_text.substring("mailto:"sv.length());
    if (url.scheme() == "tel"sv)
        return url_text.substring("tel:"sv.length());
    return url_text;
}

}
