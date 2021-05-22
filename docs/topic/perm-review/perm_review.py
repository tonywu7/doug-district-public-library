# MIT License
#
# Copyright (c) 2021 tonyzbf +https://github.com/tonyzbf/
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import annotations

import dataclasses
import io
import os
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from functools import cached_property, reduce
from operator import and_
from typing import Dict, Iterable, List, Set, Tuple

import pandas as pd
from termcolor import colored

VIEW_PUBLIC_CHANNELS = 'view_public_channels'
VIEW_CHANNEL = 'view_channel'
MANAGE_CHANNELS = 'manage_channels'
MANAGE_ROLES = 'manage_roles'
MANAGE_EMOJIS = 'manage_emojis'
AUDIT_LOG = 'audit_log'
SERVER_INSIGHTS = 'server_insights'
WEBHOOKS = 'webhooks'
MANAGE_SERVER = 'manage_server'

INVITE = 'invite'
CHANGE_NICKNAME = 'change_nickname'
MANAGE_NICKNAMES = 'manage_nicknames'
KICK_MEMBERS = 'kick_members'
BAN_MEMBERS = 'ban_members'

SEND_MESSAGES = 'send_messages'
EMBED_LINKS = 'embed_links'
ATTACH_FILES = 'attach_files'
ADD_REACTIONS = 'add_reactions'
EXTERN_EMOTES = 'extern_emotes'
MASS_MENTIONS = 'mass_mentions'
MANAGE_MESSAGES = 'manage_messages'
MESSAGE_HISTORY = 'message_history'
TEXT_TO_SPEECH = 'text_to_speech'
SLASH_COMMANDS = 'slash_commands'

VOICE_CONNECT = 'voice_connect'
VOICE_SPEAK = 'voice_speak'
VOICE_VIDEO = 'voice_video'
VOICE_ACTIVITY = 'voice_activity'
PRIORITY_SPEAKER = 'priority_speaker'
MUTE_MEMBERS = 'mute_members'
DEAFEN_MEMBERS = 'deafen_members'
MOVE_MEMBERS = 'move_members'

REQUEST_TO_SPEAK = 'request_to_speak'

ADMINISTRATOR = 'administrator'

BASE_CHANNEL_PERMS = [VIEW_CHANNEL]
TEXT_CHANNEL_PERMS = [
    MANAGE_CHANNELS, MANAGE_ROLES, WEBHOOKS,
    INVITE, SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES,
    ADD_REACTIONS, EXTERN_EMOTES, MASS_MENTIONS,
    MANAGE_MESSAGES, MESSAGE_HISTORY,
    TEXT_TO_SPEECH, SLASH_COMMANDS,
]
VOICE_CHANNEL_PERMS = [
    MANAGE_CHANNELS, MANAGE_ROLES,
    INVITE, VOICE_CONNECT, VOICE_SPEAK, VOICE_VIDEO,
    VOICE_ACTIVITY, PRIORITY_SPEAKER,
    MUTE_MEMBERS, DEAFEN_MEMBERS, MOVE_MEMBERS,
]
STAGE_CHANNEL_PERMS = [
    VIEW_CHANNEL, MANAGE_CHANNELS, MANAGE_ROLES,
    INVITE, VOICE_CONNECT, VOICE_ACTIVITY,
    MUTE_MEMBERS, MOVE_MEMBERS, REQUEST_TO_SPEAK,
]
CHANNEL_MOD_PERMS = [
    MANAGE_CHANNELS, MANAGE_ROLES, WEBHOOKS,
    MASS_MENTIONS, MANAGE_MESSAGES,
]
MESSAGE_WRITE_PERMS = [
    EMBED_LINKS, ATTACH_FILES, MASS_MENTIONS,
    TEXT_TO_SPEECH, SLASH_COMMANDS,
]
VOICE_WRITE_PERMS = [
    VOICE_VIDEO, VOICE_ACTIVITY, PRIORITY_SPEAKER,
]
MOD_PERMS = [
    MANAGE_CHANNELS, MANAGE_ROLES, MANAGE_EMOJIS, AUDIT_LOG, SERVER_INSIGHTS,
    WEBHOOKS, MANAGE_SERVER, MANAGE_NICKNAMES, KICK_MEMBERS, BAN_MEMBERS,
    MASS_MENTIONS, MANAGE_MESSAGES, PRIORITY_SPEAKER,
    MUTE_MEMBERS, DEAFEN_MEMBERS, MOVE_MEMBERS, ADMINISTRATOR,
]

HERE = colored('@here', 'white', None, ['bold'])


class Perm(Enum):
    ALLOW = 'allow'
    PASS = 'passthrough'
    DENY = 'deny'

    def __and__(self, other: Perm) -> Perm:
        if not isinstance(other, Perm):
            return NotImplemented
        union = {self, other}
        if Perm.ALLOW in union:
            return Perm.ALLOW
        if Perm.DENY in union:
            return Perm.DENY
        return Perm.PASS

    def __or__(self, other: Perm) -> Perm:
        if not isinstance(other, Perm):
            return NotImplemented
        if other is Perm.PASS:
            return self
        return other

    def resolve(self):
        return Perm.ALLOW if bool(self) else Perm.DENY

    def __bool__(self) -> bool:
        return self is Perm.ALLOW

    def __str__(self) -> str:
        if self:
            color = 'green'
        elif self is Perm.DENY:
            color = 'red'
        else:
            color = 'white'
        return colored(self.value, color)

    def format(self, name: str):
        return f'{colored(name, None, None, ["underline"])} {self}'


@dataclass(eq=True, frozen=True)
class PermissionTable:
    def __init__(self, *, allows: Iterable[str] = (), denies: Iterable[str] = (), **perms: Perm):
        super().__init__()
        for k in allows:
            object.__setattr__(self, k, Perm.ALLOW)
        for k in denies:
            object.__setattr__(self, k, Perm.DENY)
        for k, v in perms.items():
            object.__setattr__(self, k, v)
        if self.administrator:
            for k in self.perm_names():
                object.__setattr__(self, k, Perm.ALLOW)

    def __getitem__(self, perm_name: str) -> Perm:
        try:
            return getattr(self, perm_name)
        except AttributeError:
            raise KeyError(perm_name)

    # General server permissions
    view_public_channels: Perm = Perm.PASS
    view_channel: Perm = Perm.PASS
    manage_channels: Perm = Perm.PASS
    manage_roles: Perm = Perm.PASS
    manage_emojis: Perm = Perm.PASS
    audit_log: Perm = Perm.PASS
    server_insights: Perm = Perm.PASS
    webhooks: Perm = Perm.PASS
    manage_server: Perm = Perm.PASS

    # Membership permissions
    invite: Perm = Perm.PASS
    change_nickname: Perm = Perm.PASS
    manage_nicknames: Perm = Perm.PASS
    kick_members: Perm = Perm.PASS
    ban_members: Perm = Perm.PASS

    # Text channel permissions
    send_messages: Perm = Perm.PASS
    embed_links: Perm = Perm.PASS
    attach_files: Perm = Perm.PASS
    add_reactions: Perm = Perm.PASS
    extern_emotes: Perm = Perm.PASS
    mass_mentions: Perm = Perm.PASS
    manage_messages: Perm = Perm.PASS
    message_history: Perm = Perm.PASS
    text_to_speech: Perm = Perm.PASS
    slash_commands: Perm = Perm.PASS

    # Voice channel permissions
    voice_connect: Perm = Perm.PASS
    voice_speak: Perm = Perm.PASS
    voice_video: Perm = Perm.PASS
    voice_activity: Perm = Perm.PASS
    priority_speaker: Perm = Perm.PASS
    mute_members: Perm = Perm.PASS
    deafen_members: Perm = Perm.PASS
    move_members: Perm = Perm.PASS

    # Stage channel permissions
    request_to_speak: Perm = Perm.PASS

    administrator: Perm = Perm.PASS

    def __and__(self, other: PermissionTable) -> PermissionTable:
        if not isinstance(other, PermissionTable):
            return NotImplemented
        perms = {}
        for k in self.perm_names():
            perms[k] = getattr(self, k) & getattr(other, k)
        return PermissionTable(**perms)

    def __or__(self, other: PermissionTable) -> PermissionTable:
        if not isinstance(other, PermissionTable):
            return NotImplemented
        perms = {}
        for k in self.perm_names():
            perms[k] = getattr(self, k) | getattr(other, k)
        return PermissionTable(**perms)

    def is_allowed_to(self, perm: str):
        return bool(getattr(self, perm))

    def to_dataframe(self, mask: List[str] = None, name: str = 'value') -> pd.DataFrame:
        df = pd.DataFrame(index=pd.Index(self.perm_names(), name='permission'), columns=[name],
                          data=[(v & self.administrator).value for v in dataclasses.asdict(self).values()])
        if mask:
            df = df.loc[mask, :]
        return df.replace('passthrough', '')

    @classmethod
    def perm_names(cls):
        return [p.name for p in dataclasses.fields(cls)]

    def items(self):
        for k in self.perm_names():
            yield k, self[k]


@dataclass(eq=True, frozen=True)
class Role:
    name: str
    priority: int
    perms: PermissionTable = dataclasses.field(repr=False)

    color: str = 'white'

    def __str__(self):
        return colored(self.name, self.color, None, ['bold'])

    @cached_property
    def is_everyone(self):
        return self.name == '@everyone'

    @cached_property
    def is_admin(self):
        return bool(self.perms.administrator)

    @classmethod
    def reduce(self, perm: str, roles: Iterable[Role]) -> Perm:
        return reduce(and_, [getattr(r.perms, perm) for r in roles], Perm.PASS)


@dataclass(eq=True, frozen=True)
class Channel:
    name: str
    baseline: Role = dataclasses.field(repr=False)
    settings: Dict[Role, PermissionTable] = dataclasses.field(repr=False)

    def __init__(self, name: str, baseline: PermissionTable, settings: Dict[Role, PermissionTable]) -> None:
        object.__setattr__(self, 'name', name)
        object.__setattr__(self, 'baseline', Role('@here', -1, baseline))
        object.__setattr__(self, 'settings', settings)

    def __str__(self):
        return colored(self.name, None, None, ['bold'])

    def join(self, member: Member) -> Member:
        common_roles = {Role(r.name, -1, perms=self.settings[r]) for r
                        in (member.roles & self.settings.keys()) - {EVERYONE}}
        return Member('|'.join([r.name for r in common_roles]), common_roles)

    def eval_visibility(self, role: Role, perms: PermissionTable):
        for k in {*TEXT_CHANNEL_PERMS, *VOICE_CHANNEL_PERMS}:
            p = getattr(perms, k)
            if p is not Perm.PASS:
                yield ChannelInvisible(role, p, k)

    def eval_text_write_access(self, role: Role, perms: PermissionTable):
        for k in MESSAGE_WRITE_PERMS:
            p = getattr(perms, k)
            if p is not Perm.PASS:
                yield TextChannelReadOnly(role, p, k)

    def eval_voice_write_access(self, role: Role, perms: PermissionTable):
        for k in VOICE_WRITE_PERMS:
            p = getattr(perms, k)
            if p is not Perm.PASS:
                yield VoiceChannelReadOnly(role, p, k)

    def eval_advanced_perms(self, server_perm: Perm, here_perm: Perm, channel_perm: Perm,
                            perm_name: str, channel: Channel, role: Role) -> List[Issue] | None:
        issues = {
            (Perm.PASS, Perm.ALLOW, Perm.ALLOW): lambda: [
                RedundantChannelBaseline(perm_name, channel_perm, role),
            ],
            (Perm.PASS, Perm.ALLOW, Perm.DENY): lambda: [
                OverridesHere(perm_name, here_perm, channel_perm, role),
            ],
            (Perm.PASS, Perm.DENY, Perm.ALLOW): lambda: [
                OverridesHere(perm_name, here_perm, channel_perm, role),
            ],
            (Perm.PASS, Perm.DENY, Perm.DENY): lambda: [
                RedundantChannelBaseline(perm_name, channel_perm, role),
            ],
            (Perm.ALLOW, Perm.PASS, Perm.ALLOW): lambda: [
                RedundantInherited(perm_name, server_perm, role),
            ],
            (Perm.ALLOW, Perm.PASS, Perm.DENY): lambda: [
                OverridesSelf(perm_name, server_perm, channel_perm, role),
            ],
            (Perm.ALLOW, Perm.ALLOW, Perm.ALLOW): lambda: [
                RedundantInherited(perm_name, server_perm, role),
            ],
            (Perm.ALLOW, Perm.ALLOW, Perm.DENY): lambda: [
                OverridesSelf(perm_name, server_perm, channel_perm, role),
            ],
            (Perm.ALLOW, Perm.DENY, Perm.ALLOW): lambda: [
                OverridesRole(perm_name, server_perm, here_perm, role),
                OverridesHere(perm_name, here_perm, channel_perm, role),
            ],
            (Perm.ALLOW, Perm.DENY, Perm.DENY): lambda: [
                OverridesRole(perm_name, server_perm, here_perm, role),
                RedundantChannelBaseline(perm_name, channel_perm, role),
            ],
        }
        issue = issues.get((server_perm, here_perm, channel_perm))
        if issue:
            return issue()

    def evaluate(self):
        perm_names = PermissionTable.perm_names()
        here_perms = self.baseline.perms

        if not here_perms.view_channel:
            yield from self.eval_visibility(self.baseline, here_perms)
        if not here_perms.send_messages:
            yield from self.eval_text_write_access(self.baseline, here_perms)
        if not here_perms.voice_connect:
            yield from self.eval_voice_write_access(self.baseline, here_perms)

        for role, perms in self.settings.items():
            if role.is_admin:
                yield RoleIsAdmin(role)
                continue

            server_perms = role.perms
            has_changes = False

            for p in perm_names:
                p_server = getattr(server_perms, p)
                p_here = getattr(here_perms, p)
                p_channel = getattr(perms, p)
                has_changes = has_changes or p_channel is not Perm.PASS
                issues = self.eval_advanced_perms(p_server, p_here, p_channel, p, self, role)
                if issues:
                    yield from issues

            visible = server_perms.view_public_channels | here_perms.view_channel | perms.view_channel
            if not visible:
                yield from self.eval_visibility(role, perms)
            writable = server_perms.send_messages | here_perms.send_messages | perms.send_messages
            if not writable:
                yield from self.eval_text_write_access(role, perms)
            voice_connectable = server_perms.voice_connect | here_perms.voice_connect | perms.voice_connect
            if not voice_connectable:
                yield from self.eval_voice_write_access(role, perms)
            if not has_changes:
                yield RoleNoEffect(role)

    def with_member(self, member: Member):
        server_perms = member.to_dataframe().drop('* Server perms', axis=1)
        here_perms = self.baseline.perms.to_dataframe(name='@here')
        joined = self.join(member)
        channel_perms = joined.to_dataframe().drop('* Server perms', axis=1)
        columns = [f'{k}@here' for k in channel_perms.columns]
        channel_perms.columns = columns
        final_perms = (member @ self).to_dataframe(name='* Channel perms')
        total = pd.concat([server_perms, here_perms, channel_perms, final_perms], axis=1)
        return total

    @property
    def is_text_channel(self) -> bool:
        return self.name[0] == '#'


@dataclass(eq=True, frozen=True)
class Member:
    name: str
    roles: Set[Role]

    @cached_property
    def perms(self) -> PermissionTable:
        return reduce(and_, [r.perms for r in self.roles], PermissionTable())

    def has_permission(self, perm: str):
        return bool(Role.reduce(perm, self.roles))

    def __matmul__(self, channel: Channel) -> PermissionTable:
        if not isinstance(channel, Channel):
            return NotImplemented
        server_baseline = self.perms
        channel_baseline = channel.baseline.perms
        overrides = channel.join(self).perms
        return server_baseline | channel_baseline | overrides

    def evaluate(self):
        perm_map: Dict[Tuple[str, Perm], List[Role]] = defaultdict(list)
        for role in self.roles:
            for k, v in role.perms.items():
                if v is Perm.ALLOW:
                    perm_map[(k, v)].append(role)
        for (k, p), v in perm_map.items():
            if len(v) > 1:
                yield RedundantRolePermission(v, p, k)

    def __str__(self):
        return colored(self.name, None, None, ['bold'])

    def to_dataframe(self, mask: List[str] = None) -> pd.DataFrame:
        dfs = []
        for r in sorted(self.roles, key=lambda r: r.priority):
            dfs.append(r.perms.to_dataframe(mask, name=r.name))
        dfs.append(self.perms.to_dataframe(mask, name='* Server perms'))
        table = pd.concat(dfs, axis=1)
        return table


class Issue:
    code: str
    color: str

    def format_str(self) -> str:
        raise NotImplementedError

    def __str__(self):
        head = colored(f'{self.code}:', self.color, None, ['bold'])
        return f'{head} {self.format_str()}'


class RedundantRolePermission(Issue):
    code = 'W06 repeated perm'
    color = 'yellow'

    def __init__(self, roles: List[Role], perm: Perm, perm_name: str) -> None:
        self.fmt_str = f'{perm.format(perm_name)} set by more than one roles: {", ".join([str(r) for r in roles])}'

    def format_str(self) -> str:
        return self.fmt_str


class RoleNoEffect(Issue):
    code = 'W01 useless role'
    color = 'yellow'

    def __init__(self, role: Role) -> None:
        self.fmt_str = f'{role} does not change any settings'

    def format_str(self) -> str:
        return self.fmt_str


class RoleIsAdmin(Issue):
    code = 'W02 administrator'
    color = 'yellow'

    def __init__(self, role: Role, *args, **kwargs):
        assert bool(role.perms.administrator)
        self.fmt_str = f'{role} is already administrator - channel perms have no effect'

    def format_str(self) -> str:
        return self.fmt_str


class ChannelInvisible(Issue):
    code = 'W03 channel hidden'
    color = 'yellow'

    def __init__(self, role: Role, perm: Perm, perm_name: str) -> None:
        self.fmt_str = f'{role} cannot see channel, {perm.format(perm_name)} has no effect'

    def format_str(self) -> str:
        return self.fmt_str


class TextChannelReadOnly(Issue):
    code = 'W04 no write access'
    color = 'yellow'

    def __init__(self, role: Role, perm: Perm, perm_name: str) -> None:
        self.fmt_str = f'{role} cannot send messages in channel, {perm.format(perm_name)} has no effect'

    def format_str(self) -> str:
        return self.fmt_str


class VoiceChannelReadOnly(Issue):
    code = 'W05 no audio access'
    color = 'yellow'

    def __init__(self, role: Role, perm: Perm, perm_name: str) -> None:
        self.fmt_str = f'{role} cannot speak in channel, {perm.format(perm_name)} has no effect'

    def format_str(self) -> str:
        return self.fmt_str


class OverridesHere(Issue):
    code = 'I01 overridden perm'
    color = 'blue'

    def __init__(self, perm_name: str, base_perm: Perm, perm: Perm, role: Role):
        self.fmt_str = f"{role} {perm.format(perm_name)} overrides {HERE}'s {base_perm.format(perm_name)}"

    def format_str(self) -> str:
        return self.fmt_str


class OverridesSelf(Issue):
    code = 'I02 overridden perm'
    color = 'blue'

    def __init__(self, perm_name: str, base_perm: Perm, perm: Perm, role: Role):
        self.fmt_str = f"{role} {perm.format(perm_name)} overrides {role}'s server-wide {base_perm.format(perm_name)}"

    def format_str(self) -> str:
        return self.fmt_str


class OverridesRole(Issue):
    code = 'I03 overridden perm'
    color = 'blue'

    def __init__(self, perm_name: str, base_perm: Perm, perm: Perm, role: Role):
        self.fmt_str = f"{HERE} {perm.format(perm_name)} overrides {role}'s server-wide {base_perm.format(perm_name)}"

    def format_str(self) -> str:
        return self.fmt_str


class RedundantSetting(Issue):
    color = 'red'

    def __init__(self, perm_name: str, perm: Perm, redundant: Role, *args, **kwargs):
        self.role = redundant
        perm_str = perm.format(perm_name)
        self.fmt_str = f'{redundant} {perm_str} - {self.format_reason()}'

    def format_reason(self) -> str:
        raise NotImplementedError

    def format_str(self) -> str:
        return self.fmt_str


class RedundantInherited(RedundantSetting):
    code = 'E01 redundant perm'

    def format_reason(self) -> str:
        return "can inherit from role's permissions"


class RedundantChannelBaseline(RedundantSetting):
    code = 'E02 redundant perm'

    def format_reason(self) -> str:
        return f'can inherit from {HERE}'


EVERYONE = Role(
    name='@everyone', priority=0,
    perms=PermissionTable(allows=(SLASH_COMMANDS, REQUEST_TO_SPEAK)),
)

GAME_EVENT_ORGANIZER = Role(
    name='Game Event Organizer', priority=4,
    perms=PermissionTable(allows=(SLASH_COMMANDS, REQUEST_TO_SPEAK)),
)

GAME_EVENT = Role(
    name='Game Event', priority=3,
    perms=PermissionTable(allows=(SLASH_COMMANDS, REQUEST_TO_SPEAK)),
)

MINECRAFT = Role(
    name='Minecraft', priority=5,
    perms=PermissionTable(
        allows=(VIEW_PUBLIC_CHANNELS, INVITE,
                SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES,
                EXTERN_EMOTES, MESSAGE_HISTORY,
                SLASH_COMMANDS, VOICE_CONNECT, VOICE_SPEAK,
                VOICE_ACTIVITY, REQUEST_TO_SPEAK),
    ),
)

NO_POWER = Role(
    name='no power', priority=9,
    perms=PermissionTable(allows=(SLASH_COMMANDS, REQUEST_TO_SPEAK)),
)

DANNYLING = Role(
    name='Dannyling', priority=10,
    perms=PermissionTable(allows=(
        VIEW_PUBLIC_CHANNELS,
        INVITE, CHANGE_NICKNAME,
        SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES,
        ADD_REACTIONS, EXTERN_EMOTES,
        MESSAGE_HISTORY,
        SLASH_COMMANDS,
        VOICE_CONNECT, VOICE_SPEAK,
        VOICE_VIDEO, VOICE_ACTIVITY,
        REQUEST_TO_SPEAK,
    )),
)

MUTED = Role(
    name='Muted', priority=11,
    perms=PermissionTable(allows=(SLASH_COMMANDS, REQUEST_TO_SPEAK)),
)

NO_NICKNAME = Role(
    name='mmm no nickname', priority=12,
    perms=PermissionTable(allows=(SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES,
                                  SLASH_COMMANDS, REQUEST_TO_SPEAK)),
)

SPOONIES = Role(
    name='Spoonies', priority=20,
    color='yellow',
    perms=PermissionTable(allows=(SLASH_COMMANDS, REQUEST_TO_SPEAK)),
)

TWITCH_VIP = Role(
    name='Twitch VIP', priority=21,
    color='yellow',
    perms=PermissionTable(allows=(SLASH_COMMANDS, REQUEST_TO_SPEAK)),
)

BOOSTER = Role(
    name='Pepto Bismol Spoonies', priority=22,
    color='yellow',
    perms=PermissionTable(allows=(SLASH_COMMANDS, REQUEST_TO_SPEAK)),
)

PATREON = Role(
    name='Super Patreon Deluxe for Wii U', priority=23,
    color='yellow',
    perms=PermissionTable(allows=(SLASH_COMMANDS, REQUEST_TO_SPEAK)),
)

GAMING_GODS = Role(
    name='Gaming Gods', priority=24,
    color='yellow',
    perms=PermissionTable(allows=(SLASH_COMMANDS, REQUEST_TO_SPEAK)),
)

FOUNDERS = Role(
    name='Founders', priority=25,
    color='yellow',
    perms=PermissionTable(
        allows=(VIEW_PUBLIC_CHANNELS, INVITE,
                SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES, ADD_REACTIONS,
                EXTERN_EMOTES, MESSAGE_HISTORY, SLASH_COMMANDS,
                VOICE_CONNECT, VOICE_SPEAK, VOICE_ACTIVITY, REQUEST_TO_SPEAK),
    ),
)

MC_MODS = Role(
    name='MC Mods', priority=30,
    perms=PermissionTable(
        allows=(VIEW_PUBLIC_CHANNELS, INVITE,
                SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES,
                EXTERN_EMOTES, MESSAGE_HISTORY, SLASH_COMMANDS,
                VOICE_CONNECT, VOICE_SPEAK, VOICE_VIDEO,
                VOICE_ACTIVITY, REQUEST_TO_SPEAK),
    ),
)

FUNCTIONAL_BOTS = Role(
    name='Functional Bots', priority=35,
    perms=PermissionTable(
        allows=(VIEW_PUBLIC_CHANNELS, WEBHOOKS,
                SEND_MESSAGES, MASS_MENTIONS, SLASH_COMMANDS,
                REQUEST_TO_SPEAK),
    ),
)

ZAPIER = Role(
    name='Zapier', priority=34,
    perms=PermissionTable(
        allow=(ADMINISTRATOR,),
    ),
)

NIGHTBOT = Role(
    name='Nightbot', priority=33,
    perms=PermissionTable(
        allow=(VIEW_CHANNEL, MANAGE_ROLES, SEND_MESSAGES, EMBED_LINKS, MANAGE_MESSAGES, SLASH_COMMANDS, REQUEST_TO_SPEAK),
    ),
)

RYTHM = Role(
    name='Rythm', priority=32,
    perms=PermissionTable(
        allow=(VIEW_CHANNEL, SEND_MESSAGES, MANAGE_MESSAGES, SLASH_COMMANDS, VOICE_CONNECT, VOICE_SPEAK, VOICE_VIDEO, REQUEST_TO_SPEAK),
    ),
)

MODS = Role(
    name='Mods', priority=40,
    color='magenta',
    perms=PermissionTable(
        allows=(VIEW_PUBLIC_CHANNELS, MANAGE_ROLES,
                INVITE, SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES,
                EXTERN_EMOTES, MESSAGE_HISTORY, SLASH_COMMANDS,
                VOICE_CONNECT, VOICE_SPEAK, VOICE_VIDEO,
                VOICE_ACTIVITY, REQUEST_TO_SPEAK),
    ),
)

TWITCH_MODS = Role(
    name='Twitch Mods', priority=41,
    color='magenta',
    perms=PermissionTable(
        allows=(VIEW_PUBLIC_CHANNELS, SERVER_INSIGHTS, WEBHOOKS,
                INVITE, CHANGE_NICKNAME, MANAGE_NICKNAMES, KICK_MEMBERS, BAN_MEMBERS,
                SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES, ADD_REACTIONS,
                EXTERN_EMOTES, MASS_MENTIONS, MANAGE_MESSAGES, MESSAGE_HISTORY,
                SLASH_COMMANDS, VOICE_CONNECT, VOICE_SPEAK, VOICE_VIDEO,
                VOICE_ACTIVITY, MUTE_MEMBERS, DEAFEN_MEMBERS, MOVE_MEMBERS,
                REQUEST_TO_SPEAK),
    ),
)

DISCORD_MODS = Role(
    name='Discord Mods', priority=42,
    color='magenta',
    perms=PermissionTable(
        allows=(VIEW_PUBLIC_CHANNELS, MANAGE_ROLES, AUDIT_LOG, SERVER_INSIGHTS,
                INVITE, CHANGE_NICKNAME, MANAGE_NICKNAMES, KICK_MEMBERS, BAN_MEMBERS,
                SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES, ADD_REACTIONS,
                EXTERN_EMOTES, MASS_MENTIONS, MANAGE_MESSAGES, MESSAGE_HISTORY,
                SLASH_COMMANDS, VOICE_CONNECT, VOICE_SPEAK, VOICE_VIDEO,
                VOICE_ACTIVITY, MUTE_MEMBERS, DEAFEN_MEMBERS, MOVE_MEMBERS,
                REQUEST_TO_SPEAK),
    ),
)

COMMUNITY_MANAGER = Role(
    name='Community Manager', priority=43,
    color='magenta',
    perms=PermissionTable(
        allows=(VIEW_PUBLIC_CHANNELS, MANAGE_CHANNELS, MANAGE_ROLES, MANAGE_EMOJIS,
                AUDIT_LOG, SERVER_INSIGHTS, WEBHOOKS, MANAGE_SERVER,
                INVITE, CHANGE_NICKNAME, MANAGE_NICKNAMES, KICK_MEMBERS, BAN_MEMBERS,
                SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES, ADD_REACTIONS, EXTERN_EMOTES,
                MASS_MENTIONS, MANAGE_MESSAGES, MESSAGE_HISTORY, SLASH_COMMANDS,
                VOICE_CONNECT, VOICE_SPEAK, VOICE_VIDEO, VOICE_ACTIVITY,
                MUTE_MEMBERS, DEAFEN_MEMBERS, MOVE_MEMBERS, REQUEST_TO_SPEAK),
    ),
)

BOTS = Role(name='Bots', priority=44, perms=PermissionTable(allows=(ADMINISTRATOR,)))

ADMINS = Role(name='Admins', priority=50, color='cyan', perms=PermissionTable(allows=(ADMINISTRATOR,)))

LORD_PEPPER = Role(name='Lord Pepper', priority=60, color='cyan', perms=PermissionTable(allows=(ADMINISTRATOR,)))

rules_and_info = Channel(
    name='#rules-and-info',
    baseline=PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY), denies=(ADD_REACTIONS,)),
    settings={
        NO_POWER: PermissionTable(denies=(SEND_MESSAGES,)),
        DANNYLING: PermissionTable(allows=(VIEW_CHANNEL,), denies=(SEND_MESSAGES, ADD_REACTIONS)),
        MUTED: PermissionTable(denies=(SEND_MESSAGES, ADD_REACTIONS)),
        NO_NICKNAME: PermissionTable(),
        FUNCTIONAL_BOTS: PermissionTable(
            allows=(VIEW_CHANNEL, WEBHOOKS, SEND_MESSAGES, MANAGE_MESSAGES),
        ),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL,)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        ADMINS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        LORD_PEPPER: PermissionTable(allows=TEXT_CHANNEL_PERMS),
    },
)

announcements = Channel(
    name='#announcements',
    baseline=PermissionTable(allows=(VIEW_CHANNEL, ADD_REACTIONS, MESSAGE_HISTORY), denies=(SEND_MESSAGES,)),
    settings={
        MUTED: PermissionTable(denies=(SEND_MESSAGES, ADD_REACTIONS)),
        FUNCTIONAL_BOTS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        ADMINS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        LORD_PEPPER: PermissionTable(allows=TEXT_CHANNEL_PERMS),
    },
)

content = Channel(
    name='#content',
    baseline=PermissionTable(allows=(VIEW_CHANNEL, EMBED_LINKS, ADD_REACTIONS, MESSAGE_HISTORY),
                             denies=(SEND_MESSAGES, ATTACH_FILES)),
    settings={
        DANNYLING: PermissionTable(allows=(VIEW_CHANNEL, EMBED_LINKS), denies=(SEND_MESSAGES,)),
        MUTED: PermissionTable(denies=(SEND_MESSAGES, ADD_REACTIONS)),
        FUNCTIONAL_BOTS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES)),
        ZAPIER: PermissionTable(allows=(VIEW_CHANNEL, WEBHOOKS, SEND_MESSAGES, EMBED_LINKS,
                                        ATTACH_FILES, ADD_REACTIONS, EXTERN_EMOTES, MANAGE_MESSAGES, MESSAGE_HISTORY)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        ADMINS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        LORD_PEPPER: PermissionTable(allows=TEXT_CHANNEL_PERMS),
    },
)

role_assignments = Channel(
    name='#role-assignments',
    baseline=PermissionTable(denies=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS)),
    settings={
        DANNYLING: PermissionTable(allows=(VIEW_CHANNEL,), denies=(SEND_MESSAGES, ADD_REACTIONS)),
        MUTED: PermissionTable(denies=(SEND_MESSAGES, ADD_REACTIONS)),
        FUNCTIONAL_BOTS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MASS_MENTIONS)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL,)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, MESSAGE_HISTORY)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        ADMINS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        LORD_PEPPER: PermissionTable(allows=TEXT_CHANNEL_PERMS),
    },
)

welcome = Channel(
    name='#welcome',
    baseline=PermissionTable(allows=(VIEW_CHANNEL, MESSAGE_HISTORY), denies=(SEND_MESSAGES, ADD_REACTIONS)),
    settings={
        DANNYLING: PermissionTable(allows=(VIEW_CHANNEL, ADD_REACTIONS), denies=(SEND_MESSAGES,)),
        MUTED: PermissionTable(denies=(SEND_MESSAGES, ADD_REACTIONS)),
        FUNCTIONAL_BOTS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MASS_MENTIONS)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL,)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, MESSAGE_HISTORY)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        ADMINS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        LORD_PEPPER: PermissionTable(allows=TEXT_CHANNEL_PERMS),
    },
)

tweets = Channel(
    name='#tweets',
    baseline=PermissionTable(allows=(VIEW_CHANNEL, MESSAGE_HISTORY),
                             denies=(SEND_MESSAGES, ADD_REACTIONS)),
    settings={
        DANNYLING: PermissionTable(allows=(VIEW_CHANNEL, ADD_REACTIONS), denies=(SEND_MESSAGES,)),
        MUTED: PermissionTable(denies=(SEND_MESSAGES, ADD_REACTIONS)),
        FUNCTIONAL_BOTS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MASS_MENTIONS)),
        ZAPIER: PermissionTable(allows=(VIEW_CHANNEL, WEBHOOKS, SEND_MESSAGES, EMBED_LINKS,
                                        ATTACH_FILES, ADD_REACTIONS, EXTERN_EMOTES, MANAGE_MESSAGES, MESSAGE_HISTORY)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL,)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, MESSAGE_HISTORY)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        ADMINS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        LORD_PEPPER: PermissionTable(allows=TEXT_CHANNEL_PERMS),
    },
)

_hangouts = {
    'baseline': PermissionTable(denies=(VIEW_CHANNEL, SEND_MESSAGES)),
    'settings': {
        NO_POWER: PermissionTable(denies=(EMBED_LINKS, ATTACH_FILES)),
        DANNYLING: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS, EXTERN_EMOTES, MESSAGE_HISTORY)),
        MUTED: PermissionTable(allows=(VIEW_CHANNEL,), denies=(SEND_MESSAGES, ADD_REACTIONS)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MANAGE_MESSAGES, MESSAGE_HISTORY)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MANAGE_MESSAGES, MESSAGE_HISTORY)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        ADMINS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
    },
}

general = Channel(
    name='#general',
    **_hangouts,
)

elites_club = Channel(
    name='#elites-club',
    baseline=PermissionTable(denies=(VIEW_CHANNEL,)),
    settings={
        NO_POWER: PermissionTable(denies=(EMBED_LINKS, ATTACH_FILES)),
        MUTED: PermissionTable(denies=(SEND_MESSAGES, ADD_REACTIONS)),
        SPOONIES: PermissionTable(allows=(VIEW_CHANNEL,)),
        TWITCH_VIP: PermissionTable(allows=(VIEW_CHANNEL,)),
        BOOSTER: PermissionTable(allows=(VIEW_CHANNEL,)),
        PATREON: PermissionTable(denies=(VIEW_CHANNEL,)),
        GAMING_GODS: PermissionTable(allows=(VIEW_CHANNEL,)),
        FOUNDERS: PermissionTable(allows=(VIEW_CHANNEL,)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES, MANAGE_MESSAGES, MESSAGE_HISTORY)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES, MANAGE_MESSAGES, MESSAGE_HISTORY)),
    },
)

doug_mine = Channel(
    name='#doug-mine',
    **_hangouts,
)

hell = Channel(
    name='#hell',
    **_hangouts,
)

chefs_and_foodies = Channel(
    name='#chefs-and-foodies',
    baseline=PermissionTable(denies=(VIEW_CHANNEL, SEND_MESSAGES)),
    settings={
        NO_POWER: PermissionTable(denies=(EMBED_LINKS, ATTACH_FILES)),
        DANNYLING: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES, ADD_REACTIONS, EXTERN_EMOTES, MESSAGE_HISTORY)),
        MUTED: PermissionTable(allows=(VIEW_CHANNEL,), denies=(SEND_MESSAGES, ADD_REACTIONS)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MANAGE_MESSAGES, MESSAGE_HISTORY)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MANAGE_MESSAGES, MESSAGE_HISTORY)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        ADMINS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
    },
)

creative_and_artsy = Channel(
    name='#creative-and-artsy',
    **_hangouts,
)

music_and_vibes = Channel(
    name='#music-and-vibes',
    **_hangouts,
)

games_and_geeks = Channel(
    name='#games-and-geeks',
    **_hangouts,
)

pets_and_cute_things = Channel(
    name='#pets-and-cute-things',
    **_hangouts,
)

stream_clips = Channel(
    name='#stream-clips',
    **_hangouts,
)

promo_zone = Channel(
    name='#promo-zone',
    **_hangouts,
)

game_event_info = Channel(
    name='#game-event-info',
    baseline=PermissionTable(denies=(VIEW_CHANNEL, SEND_MESSAGES)),
    settings={
        GAME_EVENT_ORGANIZER: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MANAGE_MESSAGES)),
        DANNYLING: PermissionTable(allows=(VIEW_CHANNEL,), denies=(SEND_MESSAGES,)),
        MUTED: PermissionTable(denies=(SEND_MESSAGES, ADD_REACTIONS)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MANAGE_MESSAGES, MESSAGE_HISTORY)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MANAGE_MESSAGES, MESSAGE_HISTORY)),
        ADMINS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MANAGE_MESSAGES, MESSAGE_HISTORY)),
    },
)

game_event_organizing = Channel(
    name='#game-event-organizing',
    baseline=PermissionTable(denies=(VIEW_CHANNEL,)),
    settings={
        GAME_EVENT_ORGANIZER: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES)),
        DANNYLING: PermissionTable(denies=(VIEW_CHANNEL,)),
        MUTED: PermissionTable(denies=(SEND_MESSAGES, ADD_REACTIONS)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MANAGE_MESSAGES, MESSAGE_HISTORY)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MANAGE_MESSAGES, MESSAGE_HISTORY)),
        ADMINS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MANAGE_MESSAGES, MESSAGE_HISTORY)),
    },
)

game_event = Channel(
    name='#game-event',
    baseline=PermissionTable(denies=(VIEW_CHANNEL,)),
    settings={
        GAME_EVENT: PermissionTable(allows=(VIEW_CHANNEL,)),
        GAME_EVENT_ORGANIZER: PermissionTable(allows=(MANAGE_MESSAGES,)),
        MUTED: PermissionTable(denies=(SEND_MESSAGES, ADD_REACTIONS)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL,)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL,)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL,)),
        ADMINS: PermissionTable(allows=(VIEW_CHANNEL,)),
    },
)

game_event_radio = Channel(
    name='Game Event Radio',
    baseline=PermissionTable(denies=(VIEW_CHANNEL, VOICE_CONNECT)),
    settings={
        GAME_EVENT: PermissionTable(allows=(VIEW_CHANNEL, VOICE_CONNECT)),
        GAME_EVENT_ORGANIZER: PermissionTable(allows=(MANAGE_CHANNELS, MUTE_MEMBERS, MOVE_MEMBERS)),
        MUTED: PermissionTable(denies=(VIEW_CHANNEL,)),
        TWITCH_MODS: PermissionTable(allows=(MANAGE_CHANNELS, MUTE_MEMBERS, MOVE_MEMBERS)),
        DISCORD_MODS: PermissionTable(allows=(MANAGE_CHANNELS, MUTE_MEMBERS, MOVE_MEMBERS)),
    },
)

game_event_vc_1 = Channel(
    name='Game Event VC 1',
    baseline=PermissionTable(denies=(VIEW_CHANNEL, VOICE_CONNECT)),
    settings={
        GAME_EVENT: PermissionTable(allows=(VIEW_CHANNEL, VOICE_CONNECT, VOICE_ACTIVITY)),
        GAME_EVENT_ORGANIZER: PermissionTable(allows=(VIEW_CHANNEL, MANAGE_CHANNELS)),
        MUTED: PermissionTable(denies=(VOICE_SPEAK,)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL, VOICE_CONNECT)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, VOICE_CONNECT)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL, VOICE_CONNECT)),
        ADMINS: PermissionTable(allows=(VIEW_CHANNEL, VOICE_CONNECT)),
    },
)

game_event_afk = Channel(
    name='GE AFK Zone',
    baseline=PermissionTable(denies=(VIEW_CHANNEL, VOICE_CONNECT)),
    settings={
        GAME_EVENT: PermissionTable(allows=(VIEW_CHANNEL, VOICE_CONNECT), denies=(VOICE_SPEAK,)),
        DANNYLING: PermissionTable(denies=(VIEW_CHANNEL, VOICE_CONNECT)),
        MUTED: PermissionTable(denies=(VOICE_SPEAK,)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL,)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL,)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL,)),
        ADMINS: PermissionTable(allows=(VIEW_CHANNEL,)),
    },
)

_serious = {
    'baseline': PermissionTable(denies=(VIEW_CHANNEL, SEND_MESSAGES)),
    'settings': {
        NO_POWER: PermissionTable(denies=(EMBED_LINKS, ATTACH_FILES)),
        DANNYLING: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES)),
        MUTED: PermissionTable(denies=(SEND_MESSAGES, ADD_REACTIONS)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MANAGE_MESSAGES)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MANAGE_MESSAGES, MESSAGE_HISTORY)),
        ADMINS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, MANAGE_MESSAGES, MESSAGE_HISTORY)),
    },
}

im_gonna_do_it = Channel(
    name='#im-gonna-do-it',
    **_serious,
)

ive_done_it = Channel(
    name='#ive-done-it',
    **_serious,
)

supportive_af = Channel(
    name='#supportive-af',
    **_serious,
)

tech_support = Channel(
    name='#tech-support-and-discussions',
    **_serious,
)

server_relations = Channel(
    name='#server-relations',
    **_serious,
)

submit_and_discuss = Channel(
    name='#submit-and-discuss',
    baseline=PermissionTable(denies=(VIEW_CHANNEL, SEND_MESSAGES)),
    settings={
        DANNYLING: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES)),
        MUTED: PermissionTable(denies=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS, MESSAGE_HISTORY)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS, MANAGE_MESSAGES, MESSAGE_HISTORY)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS, MANAGE_MESSAGES, MESSAGE_HISTORY)),
        ADMINS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS, MANAGE_MESSAGES, MESSAGE_HISTORY)),
    },
)

_suggestions_ro = {
    'baseline': PermissionTable(denies=(VIEW_CHANNEL, SEND_MESSAGES)),
    'settings': {
        DANNYLING: PermissionTable(allows=(VIEW_CHANNEL,), denies=(SEND_MESSAGES,)),
        MUTED: PermissionTable(denies=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS, MESSAGE_HISTORY)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS, MANAGE_MESSAGES, MESSAGE_HISTORY)),
        COMMUNITY_MANAGER: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS, MANAGE_MESSAGES, MESSAGE_HISTORY)),
        ADMINS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS, MANAGE_MESSAGES, MESSAGE_HISTORY)),
    },
}

stream_suggestions = Channel(
    name='#stream-suggestions',
    **_suggestions_ro,
)

stream_music_suggestions = Channel(
    name='#stream-music-suggestions',
    **_suggestions_ro,
)

discord_suggestions = Channel(
    name='#discord-suggestions',
    **_suggestions_ro,
)

emote_suggestions = Channel(
    name='#emote-suggestions',
    **_suggestions_ro,
)

nightbot = Channel(
    name='#nightbot',
    baseline=PermissionTable(denies=(VIEW_CHANNEL, SEND_MESSAGES)),
    settings={
        NO_POWER: PermissionTable(denies=(EMBED_LINKS, ATTACH_FILES)),
        DANNYLING: PermissionTable(denies=(SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES, ADD_REACTIONS)),
        MUTED: PermissionTable(denies=(SEND_MESSAGES, ADD_REACTIONS)),
        SPOONIES: PermissionTable(allows=(SEND_MESSAGES,)),
        TWITCH_VIP: PermissionTable(allows=(SEND_MESSAGES,)),
        BOOSTER: PermissionTable(allows=(SEND_MESSAGES,)),
        GAMING_GODS: PermissionTable(allows=(SEND_MESSAGES,)),
        FOUNDERS: PermissionTable(allows=(SEND_MESSAGES,)),
        TWITCH_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES)),
        NIGHTBOT: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES)),
        RYTHM: PermissionTable(denies=(VIEW_CHANNEL, SEND_MESSAGES)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, TEXT_TO_SPEECH)),
    },
)

_voice_channels = {
    'baseline': PermissionTable(denies=(VIEW_CHANNEL, SEND_MESSAGES, TEXT_TO_SPEECH)),
    'settings': {
        NO_POWER: PermissionTable(denies=(EMBED_LINKS, ATTACH_FILES)),
        DANNYLING: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES)),
        MUTED: PermissionTable(denies=(SEND_MESSAGES, ADD_REACTIONS, VOICE_SPEAK)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, TEXT_TO_SPEECH, VOICE_CONNECT,
                                              VOICE_SPEAK, VOICE_VIDEO, MUTE_MEMBERS, DEAFEN_MEMBERS, MOVE_MEMBERS)),
        BOTS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES)),
    },
}

hangout_text = Channel(
    name='#hangout-text',
    **_voice_channels,
)

darge_barge_text = Channel(
    name='#the-darge-barge-text',
    **_voice_channels,
)

class_room_text = Channel(
    name='#class-room-text',
    **_voice_channels,
)

practice_room_text = Channel(
    name='#practice-room-text',
    **_voice_channels,
)

tahiti_text = Channel(
    name='#tahiti-text',
    baseline=PermissionTable(denies=(VIEW_CHANNEL, SEND_MESSAGES, TEXT_TO_SPEECH)),
    settings={
        NO_POWER: PermissionTable(denies=(EMBED_LINKS, ATTACH_FILES)),
        DANNYLING: PermissionTable(allows=(VIEW_CHANNEL,), denies=(SEND_MESSAGES,)),
        MUTED: PermissionTable(denies=(SEND_MESSAGES, ADD_REACTIONS)),
        DISCORD_MODS: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, TEXT_TO_SPEECH)),
    },
)

hangout = Channel(
    name='Hangout',
    **_voice_channels,
)

hangout_2 = Channel(
    name='Hangout 2',
    **_voice_channels,
)

darge_barge = Channel(
    name='THE DARGE BARGE',
    **_voice_channels,
)

class_room = Channel(
    name='Class Room',
    **_voice_channels,
)

practice_room = Channel(
    name='Practice Room',
    **_voice_channels,
)

channels = [
    rules_and_info, announcements, content, role_assignments, welcome, tweets,
    general, elites_club, doug_mine, hell, chefs_and_foodies, creative_and_artsy, music_and_vibes, games_and_geeks, pets_and_cute_things,
    stream_clips, promo_zone,
    game_event_info, game_event_organizing, game_event,
    game_event_radio, game_event_vc_1, game_event_afk,
    im_gonna_do_it, ive_done_it, supportive_af, tech_support, server_relations,
    submit_and_discuss, stream_suggestions, stream_music_suggestions, discord_suggestions, emote_suggestions,
    nightbot, hangout_text, darge_barge_text, class_room_text, practice_room_text, tahiti_text,
    hangout, hangout_2, darge_barge, class_room, practice_room,
]

role_combinations = {
    'inactive': [EVERYONE],
    'bots': [EVERYONE, BOTS],
    'functional bots': [EVERYONE, BOTS, FUNCTIONAL_BOTS],
    'dannylings': [EVERYONE, DANNYLING],
    'game event': [EVERYONE, GAME_EVENT, DANNYLING],
    'game event org': [EVERYONE, GAME_EVENT, GAME_EVENT_ORGANIZER, DANNYLING],
    'spoonies': [EVERYONE, DANNYLING, SPOONIES],
    'boosters': [EVERYONE, DANNYLING, BOOSTER],
    'spoonies & boosters': [EVERYONE, DANNYLING, SPOONIES, BOOSTER],
    'twitch vip': [EVERYONE, DANNYLING, TWITCH_VIP],
    'gaming god': [EVERYONE, DANNYLING, GAMING_GODS],
    'minecraft': [EVERYONE, MINECRAFT, DANNYLING],
    'twitch mods': [EVERYONE, MODS, TWITCH_MODS],
    'discord mods': [EVERYONE, MODS, DISCORD_MODS],
    'twitch & discord mods': [EVERYONE, MODS, TWITCH_MODS, DISCORD_MODS],
    'comm manager': [EVERYONE, MODS, TWITCH_MODS, DISCORD_MODS, COMMUNITY_MANAGER],
    'admins': [EVERYONE, ADMINS],
    'doug': [EVERYONE, LORD_PEPPER],
}

members = {k: Member(name='|'.join([r.name for r in comb]), roles=comb) for k, comb in role_combinations.items()}


def check():
    os.makedirs('export/_server', exist_ok=True)

    print('Checking channel permission issues')
    for channel in channels:
        print()
        os.makedirs(f'export/{channel.name}', exist_ok=True)
        for issue in channel.evaluate():
            if issue.code[0] in ('W', 'E'):
                print(channel, issue)
        for k, m in members.items():
            channel_member_perms = channel.with_member(m)
            if channel.is_text_channel:
                channel_member_perms = channel_member_perms.loc[[*BASE_CHANNEL_PERMS, *TEXT_CHANNEL_PERMS], :]
            else:
                channel_member_perms = channel_member_perms.loc[[*BASE_CHANNEL_PERMS, *VOICE_CHANNEL_PERMS], :]
            channel_member_perms.to_csv(f'export/{channel.name}/{m.name}.csv')

    print()
    print('Checking role permission issues')
    for k, m in members.items():
        print()
        m.to_dataframe().to_csv(f'export/_server/{m.name}.csv')
        for issue in m.evaluate():
            if issue.code[0] in ('W', 'E'):
                print(k, issue)


def export_html(df: pd.DataFrame, name: str, index_names=False, justify='unset', escape=False, **options):
    markups = {
        'allow': '<i class="bi bi-check-circle perm-allow"></i>',
        'deny': '<i class="bi bi-x-circle perm-deny"></i>',
        '@everyone': '<span class="mention roleMention-2Bj0ju wrapper-3WhCwL mention" tabindex="-1" role="button">@everyone</span>',
        '@here': '<span class="mention roleMention-2Bj0ju wrapper-3WhCwL mention" tabindex="-1" role="button">@here</span>',
        '@Game Event': '<span class="mention roleMention-2Bj0ju wrapper-3WhCwL mention" color="0" tabindex="-1" role="button">@Game Event</span>',
        '@Game Event Organizer': '<span class="mention roleMention-2Bj0ju wrapper-3WhCwL mention" color="0" tabindex="-1" role="button">@Game Event Organizer</span>',
        '@Bot': '<span class="mention roleMention-2Bj0ju" style="color: rgb(96, 125, 139); background-color: rgba(96, 125, 139, 0.1);">@Bot</span>',
        '@Muted': '<span class="mention roleMention-2Bj0ju" style="color: rgb(84, 110, 122); background-color: rgba(84, 110, 122, 0.1);">@Muted</span>',
        '@Text-only': '<span class="mention roleMention-2Bj0ju" style="color: rgb(96, 125, 139); background-color: rgba(96, 125, 139, 0.1);">@Text-only</span>',
        '@Dannyling': '<span class="mention roleMention-2Bj0ju" style="color: rgb(26, 188, 156); background-color: rgba(26, 188, 156, 0.1);">@Dannyling</span>',
        '@Spoonie': '<span class="mention roleMention-2Bj0ju" style="color: rgb(241, 196, 15); background-color: rgba(241, 196, 15, 0.1);">@Spoonie</span>',
        '@Twitch VIP': '<span class="mention roleMention-2Bj0ju" style="color: rgb(223, 181, 214); background-color: rgba(223, 181, 214, 0.1);">@Twitch VIP</span>',
        '@Pepto Bismol Spoonie': '<span class="mention roleMention-2Bj0ju" style="color: rgb(244, 127, 255); background-color: rgba(244, 127, 255, 0.1);">@Pepto Bismol Spoonie</span>',
        '@Gaming God': '<span class="mention roleMention-2Bj0ju" style="color: rgb(46, 204, 113); background-color: rgba(46, 204, 113, 0.1);">@Gaming God</span>',
        '@Founder': '<span class="mention roleMention-2Bj0ju" style="color: rgb(113, 212, 63); background-color: rgba(113, 212, 63, 0.1);">@Founder</span>',
        '@Integration Bot': '<span class="mention roleMention-2Bj0ju" style="color: rgb(84, 110, 122); background-color: rgba(84, 110, 122, 0.1);">@Integration Bot</span>',
        '@Utility Bot': '<span class="mention roleMention-2Bj0ju" style="color: rgb(52, 152, 219); background-color: rgba(52, 152, 219, 0.1);">@Utility Bot</span>',
        '@Mod': '<span class="mention roleMention-2Bj0ju" style="color: rgb(233, 30, 98); background-color: rgba(233, 30, 98, 0.1);">@Mod</span>',
        '@Twitch Mod': '<span class="mention roleMention-2Bj0ju" style="color: rgb(191, 63, 255); background-color: rgba(191, 63, 255, 0.1);">@Twitch Mod</span>',
        '@Discord Mod': '<span class="mention roleMention-2Bj0ju" style="color: rgb(114, 137, 218); background-color: rgba(114, 137, 218, 0.1);">@Discord Mod</span>',
        '@Community Manager': '<span class="mention roleMention-2Bj0ju" style="color: rgb(157, 76, 255); background-color: rgba(157, 76, 255, 0.1);">@Community Manager</span>',
        '@Admin Bot': '<span class="mention roleMention-2Bj0ju" style="color: rgb(231, 76, 60); background-color: rgba(231, 76, 60, 0.1);">@Admin Bot</span>',
        '@Admin': '<span class="mention roleMention-2Bj0ju" style="color: rgb(41, 255, 255); background-color: rgba(41, 255, 255, 0.1);">@Admin</span>',
    }
    fn = io.StringIO()
    df.rename(columns=markups).replace(markups).to_html(fn, index_names=index_names, justify=justify,
                                                        escape=escape, **options)
    with open(name, 'w+') as f:
        table = fn.getvalue().replace('border="1" ', '').replace(' style="text-align: unset;"', '')
        f.write(f'<div class="table-container"><span class="table-title-defer"></span>{table}</div>')
    fn.close()


_ACCESS_ONLY = PermissionTable(allows=(VIEW_CHANNEL,))
_NO_ACCESS = PermissionTable(denies=(VIEW_CHANNEL,))

r_bot = Role(
    name='@Bot', perms=PermissionTable(
        allows=(MANAGE_ROLES, SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES, ADD_REACTIONS, EXTERN_EMOTES, MASS_MENTIONS,
                MANAGE_MESSAGES, MESSAGE_HISTORY, VOICE_CONNECT, VOICE_SPEAK, VOICE_VIDEO),
    ), priority=10,
)
r_integration_bot = Role(
    name='@Integration Bot', perms=PermissionTable(
        allows=(MANAGE_CHANNELS, WEBHOOKS, AUDIT_LOG),
    ), priority=30,
)
r_utility_bot = Role(
    name='@Utility Bot', perms=PermissionTable(
        allows=(MUTE_MEMBERS, DEAFEN_MEMBERS, MOVE_MEMBERS),
    ), priority=35,
)
r_admin_bot = Role(name='Admin Bot', perms=PermissionTable(allows=(ADMINISTRATOR,)), priority=85)

r_mod = Role(
    name='@Mod', perms=PermissionTable(
        allows=(MANAGE_ROLES, KICK_MEMBERS, BAN_MEMBERS, MASS_MENTIONS,
                MANAGE_MESSAGES, PRIORITY_SPEAKER, MUTE_MEMBERS, DEAFEN_MEMBERS, MOVE_MEMBERS),
    ), priority=50,
)
r_twitch_mod = Role(
    name='@Twitch Mod', perms=PermissionTable(
        allows=(),
    ), priority=60,
)
r_discord_mod = Role(
    name='@Discord Mod', perms=PermissionTable(
        allows=(AUDIT_LOG, SERVER_INSIGHTS, WEBHOOKS, MANAGE_NICKNAMES),
    ), priority=70,
)
r_comm_manager = Role(
    name='@Community Manager', perms=PermissionTable(
        allows=(MANAGE_CHANNELS, MANAGE_EMOJIS, MANAGE_SERVER),
    ), priority=80,
)

r_everyone = Role(name='@everyone', priority=0, perms=PermissionTable())
r_dannyling = Role(
    name='@Dannyling', priority=20,
    perms=PermissionTable(allows=(
        VIEW_PUBLIC_CHANNELS, INVITE, CHANGE_NICKNAME,
        SEND_MESSAGES, EMBED_LINKS, ATTACH_FILES, ADD_REACTIONS, EXTERN_EMOTES,
        MESSAGE_HISTORY, VOICE_CONNECT, VOICE_SPEAK, VOICE_VIDEO, VOICE_ACTIVITY,
        REQUEST_TO_SPEAK,
    )),
)
r_muted = Role(name='Muted', priority=11, perms=PermissionTable())
r_text = Role(name='Text-only', priority=12, perms=PermissionTable())
r_spoonie = Role(
    name='@Spoonie', priority=20,
    perms=PermissionTable(),
)

r_twitch_vip = Role(
    name='@Twitch VIP', priority=21,
    perms=PermissionTable(),
)

r_booster = Role(
    name='@Pepto Bismol Spoonie', priority=22,
    perms=PermissionTable(),
)

r_patreon = Role(
    name='@Super Patreon Deluxe for Wii U', priority=23,
    perms=PermissionTable(),
)

r_gaming_god = Role(
    name='@Gaming God', priority=24,
    perms=PermissionTable(),
)

r_founder = Role(
    name='@Founder', priority=25,
    perms=PermissionTable(),
)

r_official_dougdoug = Channel(
    name='#official-dougdoug',
    baseline=PermissionTable(
        allows=(VIEW_CHANNEL, MESSAGE_HISTORY),
        denies=(SEND_MESSAGES, ADD_REACTIONS),
    ),
    settings={
        r_bot: PermissionTable(allows=(SEND_MESSAGES, ADD_REACTIONS)),
        r_dannyling: PermissionTable(allows=(VIEW_CHANNEL, ADD_REACTIONS)),
        r_mod: _ACCESS_ONLY,
        r_integration_bot: _ACCESS_ONLY,
        r_utility_bot: _ACCESS_ONLY,
        r_comm_manager: PermissionTable(allows=(SEND_MESSAGES, ADD_REACTIONS)),
    },
)
r_rules_and_info = Channel(
    name='#rules-and-info',
    baseline=PermissionTable(
        allows=(VIEW_CHANNEL, SEND_MESSAGES, MESSAGE_HISTORY),
        denies=(ADD_REACTIONS,),
    ),
    settings={
        r_bot: PermissionTable(allows=(SEND_MESSAGES, ADD_REACTIONS)),
        r_dannyling: PermissionTable(allows=(VIEW_CHANNEL), denies=(SEND_MESSAGES, ADD_REACTIONS)),
        r_utility_bot: _ACCESS_ONLY,
        r_mod: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS)),
    },
)
r_announcements = Channel(
    name='#announcement+content',
    baseline=PermissionTable(
        allows=(VIEW_CHANNEL,),
        denies=(SEND_MESSAGES, ADD_REACTIONS),
    ),
    settings={
        r_bot: PermissionTable(allows=(SEND_MESSAGES, ADD_REACTIONS)),
        r_dannyling: PermissionTable(allows=(VIEW_CHANNEL, ADD_REACTIONS)),
        r_mod: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS)),
        r_integration_bot: _ACCESS_ONLY,
        r_utility_bot: _ACCESS_ONLY,
    },
)
r_role_assignment = Channel(
    name='#role-assignment',
    baseline=PermissionTable(
        allows=(VIEW_CHANNEL, MESSAGE_HISTORY),
        denies=(SEND_MESSAGES, ADD_REACTIONS),
    ),
    settings={
        r_bot: PermissionTable(allows=(SEND_MESSAGES, ADD_REACTIONS)),
        r_dannyling: PermissionTable(allows=(VIEW_CHANNEL,)),
        r_mod: _ACCESS_ONLY,
        r_integration_bot: _ACCESS_ONLY,
        r_utility_bot: _ACCESS_ONLY,
        r_comm_manager: PermissionTable(allows=(SEND_MESSAGES, ADD_REACTIONS)),
    },
)
r_hangouts = Channel(
    name='#hangouts',
    baseline=_NO_ACCESS,
    settings={
        r_dannyling: _ACCESS_ONLY,
        r_utility_bot: _ACCESS_ONLY,
        r_mod: _ACCESS_ONLY,
    },
)
r_elites_club = Channel(
    name='#elites-club',
    baseline=_NO_ACCESS,
    settings={
        r_spoonie: _ACCESS_ONLY,
        r_twitch_vip: _ACCESS_ONLY,
        r_booster: _ACCESS_ONLY,
        r_gaming_god: _ACCESS_ONLY,
        r_founder: _ACCESS_ONLY,
        r_utility_bot: _ACCESS_ONLY,
        r_mod: _ACCESS_ONLY,
    },
)
r_mod_district = Channel(
    name='#mods',
    baseline=_NO_ACCESS,
    settings={
        r_integration_bot: _ACCESS_ONLY,
        r_utility_bot: _ACCESS_ONLY,
        r_mod: _ACCESS_ONLY,
    },
)
r_game_event_organizer = Role(
    name='@Game Event Organizer', priority=4,
    perms=PermissionTable(),
)

r_game_event = Role(
    name='@Game Event', priority=3,
    perms=PermissionTable(),
)
r_seasonal = Channel(
    name='#seasonal',
    baseline=_NO_ACCESS,
    settings={
        r_game_event_organizer: PermissionTable(
            allows=(VIEW_CHANNEL, MANAGE_CHANNELS, PRIORITY_SPEAKER,
                    MUTE_MEMBERS, DEAFEN_MEMBERS, MOVE_MEMBERS),
        ),
        r_game_event: _ACCESS_ONLY,
        r_utility_bot: _ACCESS_ONLY,
        r_mod: _ACCESS_ONLY,
    },
)
r_seasonal_vc = Channel(
    name='seasonal',
    baseline=_NO_ACCESS,
    settings={
        r_game_event_organizer: PermissionTable(
            allows=(VIEW_CHANNEL, MANAGE_CHANNELS, PRIORITY_SPEAKER,
                    MUTE_MEMBERS, DEAFEN_MEMBERS, MOVE_MEMBERS),
        ),
        r_game_event: _ACCESS_ONLY,
        r_utility_bot: _ACCESS_ONLY,
        r_mod: _ACCESS_ONLY,
    },
)
r_geo = Channel(
    name='#geo',
    baseline=_NO_ACCESS,
    settings={
        r_game_event_organizer: PermissionTable(
            allows=(VIEW_CHANNEL, MANAGE_CHANNELS, PRIORITY_SPEAKER,
                    MUTE_MEMBERS, DEAFEN_MEMBERS, MOVE_MEMBERS),
        ),
        r_utility_bot: _ACCESS_ONLY,
        r_mod: _ACCESS_ONLY,
    },
)
r_ginfo = Channel(
    name='#ginfo',
    baseline=_NO_ACCESS,
    settings={
        r_game_event_organizer: PermissionTable(
            allows=(VIEW_CHANNEL, SEND_MESSAGES, MANAGE_CHANNELS, MANAGE_MESSAGES, PRIORITY_SPEAKER,
                    MUTE_MEMBERS, DEAFEN_MEMBERS, MOVE_MEMBERS),
        ),
        r_dannyling: PermissionTable(allows=(VIEW_CHANNEL,), denies=(SEND_MESSAGES,)),
        r_utility_bot: _ACCESS_ONLY,
        r_mod: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES)),
    },
)
r_suggestions = Channel(
    name='#suggestions',
    baseline=_NO_ACCESS,
    settings={
        r_dannyling: PermissionTable(allows=(VIEW_CHANNEL,), denies=(SEND_MESSAGES,)),
        r_utility_bot: _ACCESS_ONLY,
        r_mod: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES)),
    },
)
r_suggest_and_discuss = Channel(
    name='#suggest-and-discuss',
    baseline=_NO_ACCESS,
    settings={
        r_dannyling: _ACCESS_ONLY,
        r_utility_bot: _ACCESS_ONLY,
        r_mod: _ACCESS_ONLY,
    },
)
r_nightbot = Channel(
    name='#nightbot',
    baseline=_NO_ACCESS,
    settings={
        r_dannyling: PermissionTable(allows=(VIEW_CHANNEL,), denies=(SEND_MESSAGES, ADD_REACTIONS)),
        r_spoonie: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS)),
        r_twitch_vip: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS)),
        r_booster: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS)),
        r_gaming_god: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS)),
        r_founder: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS)),
        r_utility_bot: _ACCESS_ONLY,
        r_mod: PermissionTable(allows=(VIEW_CHANNEL, SEND_MESSAGES, ADD_REACTIONS)),
    },
)


def proposed_mod_roles():
    roles = (r_mod, r_twitch_mod, r_discord_mod, r_comm_manager, ADMINS)
    members = {
        'Twitch Mod': [r_mod, r_twitch_mod],
        'Discord Mod': [r_mod, r_discord_mod],
        'Communit Manager': [r_mod, r_discord_mod, r_comm_manager],
        'Admins': [ADMINS],
    }
    members = {k: Member(name=k, roles=v) for k, v in members.items()}

    dfs = [r.perms.to_dataframe(name=r.name, mask=MOD_PERMS) for r in roles]
    roleperms = pd.concat(dfs, axis=1)

    dfs2 = [m.perms.to_dataframe(name=m.name, mask=MOD_PERMS) for m in members.values()]
    memberperms = pd.concat(dfs2, axis=1)

    for name, df in zip(('roles.html', 'members.html'), (roleperms, memberperms)):
        export_html(df, name)


def proposed_bot_roles():
    roles = [r_bot, r_integration_bot, r_utility_bot, r_admin_bot]
    members = {
        'Integration Bot': [r_bot, r_integration_bot],
        'Utility Bot': [r_bot, r_utility_bot],
        'Admin Bot': [r_admin_bot],
    }
    members = {k: Member(name=k, roles=v) for k, v in members.items()}

    dfs = [r.perms.to_dataframe(name=r.name) for r in roles]
    roleperms = pd.concat(dfs, axis=1)

    dfs2 = [m.perms.to_dataframe(name=m.name) for m in members.values()]
    memberperms = pd.concat(dfs2, axis=1)

    for name, df in zip(('roles.html', 'members.html'), (roleperms, memberperms)):
        export_html(df, name)


def readable_perms(perms: PermissionTable, name: str) -> pd.DataFrame:
    df = perms.to_dataframe(name=name)
    df = df.replace('', 'deny')
    if not perms.view_channel:
        df.loc[:, :] = 'deny'
        return df
    if not perms.send_messages:
        df.loc[MESSAGE_WRITE_PERMS, :] = 'deny'
    if not perms.voice_connect:
        df.loc[VOICE_WRITE_PERMS, :] = 'deny'
    if not perms.add_reactions:
        df.loc[EXTERN_EMOTES, :] = 'deny'
    return df


def proposed_server_roles_channels(members: Dict[str, List[Role]], channels: List[Channel]):
    members = {k: Member(name=k, roles=v) for k, v in members.items()}
    for channel in channels:
        if channel.is_text_channel:
            mask = {k: None for k in [*BASE_CHANNEL_PERMS, *TEXT_CHANNEL_PERMS, *CHANNEL_MOD_PERMS]}
        else:
            mask = {k: None for k in [*BASE_CHANNEL_PERMS, *VOICE_CHANNEL_PERMS, *CHANNEL_MOD_PERMS]}
        settings = []
        settings.append(channel.baseline.perms.to_dataframe(mask, name='@everyone'))
        for role, perm_settings in channel.settings.items():
            settings.append(perm_settings.to_dataframe(mask, name=role.name))
        channel_settings = pd.concat(settings, axis=1)
        export_html(channel_settings, f'{channel.name}-settings.html')
        effective_perms = []
        for member in members.values():
            effective = member.perms | (member @ channel)
            effective_perms.append(readable_perms(effective, member.name).loc[mask, :])
        effective_settings = pd.concat(effective_perms, axis=1)
        export_html(effective_settings, f'{channel.name}-perms.html')


standard_members = {
    '@everyone': [r_everyone],
    '@Dannyling': [r_everyone, r_dannyling],
    '@Spoonie': [r_everyone, r_dannyling, r_spoonie],
    '@Twitch Mod': [r_everyone, r_dannyling, r_mod, r_twitch_mod],
    '@Discord Mod': [r_everyone, r_dannyling, r_mod, r_discord_mod],
    '@Community Manager': [r_everyone, r_dannyling, r_mod, r_discord_mod, r_comm_manager],
    '@Integration Bot': [r_everyone, r_bot, r_integration_bot],
    '@Utility Bot': [r_everyone, r_bot, r_utility_bot],
}
game_event_members = {
    '@everyone': [r_everyone],
    '@Dannyling': [r_everyone, r_dannyling],
    '@Game Event': [r_everyone, r_dannyling, r_game_event],
    '@Game Event Organizer': [r_everyone, r_dannyling, r_game_event_organizer],
    '@Twitch Mod': [r_everyone, r_dannyling, r_mod, r_twitch_mod],
    '@Discord Mod': [r_everyone, r_dannyling, r_mod, r_discord_mod],
    '@Community Manager': [r_everyone, r_dannyling, r_mod, r_discord_mod, r_comm_manager],
    '@Integration Bot': [r_everyone, r_bot, r_integration_bot],
    '@Utility Bot': [r_everyone, r_bot, r_utility_bot],
}

if __name__ == '__main__':
    proposed_server_roles_channels(standard_members, [r_nightbot])
