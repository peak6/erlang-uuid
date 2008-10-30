%% @author Travis Vachon
%% @author Andrew Kreiling <akreiling@pobox.com>
%% @copyright
%%      2008 Travis Vachon,
%%      2008 Andrew Kreiling <akreiling@pobox.com>.
%%  All Rights Reserved.
%% @doc
%% UUID module for Erlang
%%
%% This Erlang module was designed to be a simple library for generating UUIDs. It
%% conforms to RFC 4122 whenever possible.
%%
-module(uuid).
-author('Travis Vachon').
-author('Andrew Kreiling <akreiling@pobox.com>').
-export([v4/0, random/0, srandom/0, sha/2, md5/2, to_string/1]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(UUID_DNS_NAMESPACE, <<107,167,184,16,157,173,17,209,128,180,0,192,79,212,48,200>>).
-define(UUID_URL_NAMESPACE, <<107,167,184,17,157,173,17,209,128,180,0,192,79,212,48,200>>).
-define(UUID_OID_NAMESPACE, <<107,167,184,18,157,173,17,209,128,180,0,192,79,212,48,200>>).
-define(UUID_X500_NAMESPACE, <<107,167,184,20,157,173,17,209,128,180,0,192,79,212,48,200>>).

%% @type uuid() = binary(). A binary representation of a UUID

%% @spec v4() -> uuid()
%% @equiv random()
%% @deprecated Please use the function random() instead.
%%
v4() ->
    random().

%% @spec random() -> uuid()
%% @doc
%% Generates a random UUID
%%
random() ->
    U = <<
    (random:uniform(4294967295)):32,
    (random:uniform(4294967295)):32,
    (random:uniform(4294967295)):32,
    (random:uniform(4294967295)):32
    >>,
    format_uuid(U, 4).

%% @spec srandom() -> uuid()
%% @doc
%% Seeds random number generation with erlang:now() and generates a random UUID
%%
srandom() ->
    {A1,A2,A3} = now(),
    random:seed(A1, A2, A3),
    random().

%% @spec sha(Namespace, Name) -> uuid()
%% where
%%      Namespace = dns | url | oid | x500 | uuid()
%%      Name = list() | binary()
%% @doc
%% Generates a UUID based on a crypto:sha() hash
%%
sha(Namespace, Name) when is_list(Name) ->
    sha(Namespace, list_to_binary(Name));

sha(Namespace, Name) ->
    Context = crypto:sha_update(crypto:sha_update(crypto:sha_init(), namespace(Namespace)), Name),
    U = crypto:sha_final(Context),
    format_uuid(U, 5).

%% @spec md5(Namespace, Name) -> uuid()
%% where
%%      Namespace = dns | url | oid | x500 | uuid()
%%      Name = list() | binary()
%% @doc
%% Generates a UUID based on a crypto:md5() hash
%%
md5(Namespace, Name) when is_list(Name) ->
    md5(Namespace, list_to_binary(Name));

md5(Namespace, Name) ->
    Context = crypto:md5_update(crypto:md5_update(crypto:md5_init(), namespace(Namespace)), Name),
    U = crypto:md5_final(Context),
    format_uuid(U, 3).

%% @spec to_string(UUID) -> string()
%% where
%%      UUID = uuid()
%% @doc
%% Generates a string representation of a UUID
%%
to_string(<<TL:32, TM:16, THV:16, CSR:8, CSL:8, N:48>> = _UUID) ->
    lists:flatten(io_lib:format("~8.16.0b-~4.16.0b-~4.16.0b-~2.16.0b~2.16.0b-~12.16.0b", [TL, TM, THV, CSR, CSL, N])).

namespace(dns) -> ?UUID_DNS_NAMESPACE;
namespace(url) -> ?UUID_URL_NAMESPACE;
namespace(oid) -> ?UUID_OID_NAMESPACE;
namespace(x500) -> ?UUID_X500_NAMESPACE;
namespace(UUID) when is_binary(UUID) -> UUID;
namespace(_) -> error.

format_uuid(<<TL:32, TM:16, THV:16, CSR:8, CSL:8, N:48, _Rest/binary>>, V) ->
    <<TL:32, TM:16, ((THV band 16#0fff) bor (V bsl 12)):16, ((CSR band 16#3f) bor 16#80):8, CSL:8, N:48>>.

%% vim:sw=4:sts=4:ts=4:et
