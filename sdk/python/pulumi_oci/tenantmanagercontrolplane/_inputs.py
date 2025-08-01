# coding=utf-8
# *** WARNING: this file was generated by pulumi-language-python. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import builtins as _builtins
import warnings
import sys
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
if sys.version_info >= (3, 11):
    from typing import NotRequired, TypedDict, TypeAlias
else:
    from typing_extensions import NotRequired, TypedDict, TypeAlias
from .. import _utilities

__all__ = [
    'GetAssignedSubscriptionLineItemsFilterArgs',
    'GetAssignedSubscriptionLineItemsFilterArgsDict',
    'GetAssignedSubscriptionsFilterArgs',
    'GetAssignedSubscriptionsFilterArgsDict',
    'GetDomainGovernancesFilterArgs',
    'GetDomainGovernancesFilterArgsDict',
    'GetDomainsFilterArgs',
    'GetDomainsFilterArgsDict',
    'GetLinksFilterArgs',
    'GetLinksFilterArgsDict',
    'GetOrganizationTenanciesFilterArgs',
    'GetOrganizationTenanciesFilterArgsDict',
    'GetOrganizationsFilterArgs',
    'GetOrganizationsFilterArgsDict',
    'GetRecipientInvitationsFilterArgs',
    'GetRecipientInvitationsFilterArgsDict',
    'GetSenderInvitationsFilterArgs',
    'GetSenderInvitationsFilterArgsDict',
    'GetSubscriptionAvailableRegionsFilterArgs',
    'GetSubscriptionAvailableRegionsFilterArgsDict',
    'GetSubscriptionLineItemsFilterArgs',
    'GetSubscriptionLineItemsFilterArgsDict',
    'GetSubscriptionMappingsFilterArgs',
    'GetSubscriptionMappingsFilterArgsDict',
    'GetSubscriptionsFilterArgs',
    'GetSubscriptionsFilterArgsDict',
]

MYPY = False

if not MYPY:
    class GetAssignedSubscriptionLineItemsFilterArgsDict(TypedDict):
        name: _builtins.str
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetAssignedSubscriptionLineItemsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetAssignedSubscriptionLineItemsFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetAssignedSubscriptionsFilterArgsDict(TypedDict):
        name: _builtins.str
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetAssignedSubscriptionsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetAssignedSubscriptionsFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetDomainGovernancesFilterArgsDict(TypedDict):
        name: _builtins.str
        """
        A filter to return only resources that exactly match the name given.
        """
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetDomainGovernancesFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetDomainGovernancesFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        """
        :param _builtins.str name: A filter to return only resources that exactly match the name given.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        A filter to return only resources that exactly match the name given.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetDomainsFilterArgsDict(TypedDict):
        name: _builtins.str
        """
        A filter to return only resources that exactly match the name given.
        """
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetDomainsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetDomainsFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        """
        :param _builtins.str name: A filter to return only resources that exactly match the name given.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        A filter to return only resources that exactly match the name given.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetLinksFilterArgsDict(TypedDict):
        name: _builtins.str
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetLinksFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetLinksFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetOrganizationTenanciesFilterArgsDict(TypedDict):
        name: _builtins.str
        """
        Name of the tenancy.
        """
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetOrganizationTenanciesFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetOrganizationTenanciesFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        """
        :param _builtins.str name: Name of the tenancy.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        Name of the tenancy.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetOrganizationsFilterArgsDict(TypedDict):
        name: _builtins.str
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetOrganizationsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetOrganizationsFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetRecipientInvitationsFilterArgsDict(TypedDict):
        name: _builtins.str
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetRecipientInvitationsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetRecipientInvitationsFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetSenderInvitationsFilterArgsDict(TypedDict):
        name: _builtins.str
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetSenderInvitationsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetSenderInvitationsFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetSubscriptionAvailableRegionsFilterArgsDict(TypedDict):
        name: _builtins.str
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetSubscriptionAvailableRegionsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetSubscriptionAvailableRegionsFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetSubscriptionLineItemsFilterArgsDict(TypedDict):
        name: _builtins.str
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetSubscriptionLineItemsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetSubscriptionLineItemsFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetSubscriptionMappingsFilterArgsDict(TypedDict):
        name: _builtins.str
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetSubscriptionMappingsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetSubscriptionMappingsFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


if not MYPY:
    class GetSubscriptionsFilterArgsDict(TypedDict):
        name: _builtins.str
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetSubscriptionsFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetSubscriptionsFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


