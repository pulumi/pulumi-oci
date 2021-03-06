# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'LogAnalyticsImportCustomContentChangeListArgs',
    'LogAnalyticsObjectCollectionRuleOverrideArgs',
    'LogAnalyticsPreferencesManagementItemArgs',
    'NamespaceScheduledTaskActionArgs',
    'NamespaceScheduledTaskSchedulesArgs',
    'NamespaceScheduledTaskSchedulesScheduleArgs',
    'GetLogAnalyticsEntitiesFilterArgs',
    'GetLogAnalyticsLogGroupsFilterArgs',
    'GetLogAnalyticsObjectCollectionRulesFilterArgs',
    'GetNamespaceScheduledTasksFilterArgs',
    'GetNamespacesFilterArgs',
]

@pulumi.input_type
class LogAnalyticsImportCustomContentChangeListArgs:
    def __init__(__self__, *,
                 conflict_field_display_names: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 conflict_parser_names: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 conflict_source_names: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 created_field_display_names: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 created_parser_names: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 created_source_names: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 updated_field_display_names: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 updated_parser_names: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 updated_source_names: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None):
        """
        :param pulumi.Input[Sequence[pulumi.Input[str]]] conflict_field_display_names: A list of field display names with conflicts.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] conflict_parser_names: A list of parser names with conflicts.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] conflict_source_names: A list of source names with conflicts.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] created_field_display_names: An array of created field display names.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] created_parser_names: An array of created parser names.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] created_source_names: An array of created source names.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] updated_field_display_names: An array of updated field display names.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] updated_parser_names: An array of updated parser names.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] updated_source_names: An array of updated source names.
        """
        if conflict_field_display_names is not None:
            pulumi.set(__self__, "conflict_field_display_names", conflict_field_display_names)
        if conflict_parser_names is not None:
            pulumi.set(__self__, "conflict_parser_names", conflict_parser_names)
        if conflict_source_names is not None:
            pulumi.set(__self__, "conflict_source_names", conflict_source_names)
        if created_field_display_names is not None:
            pulumi.set(__self__, "created_field_display_names", created_field_display_names)
        if created_parser_names is not None:
            pulumi.set(__self__, "created_parser_names", created_parser_names)
        if created_source_names is not None:
            pulumi.set(__self__, "created_source_names", created_source_names)
        if updated_field_display_names is not None:
            pulumi.set(__self__, "updated_field_display_names", updated_field_display_names)
        if updated_parser_names is not None:
            pulumi.set(__self__, "updated_parser_names", updated_parser_names)
        if updated_source_names is not None:
            pulumi.set(__self__, "updated_source_names", updated_source_names)

    @property
    @pulumi.getter(name="conflictFieldDisplayNames")
    def conflict_field_display_names(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        A list of field display names with conflicts.
        """
        return pulumi.get(self, "conflict_field_display_names")

    @conflict_field_display_names.setter
    def conflict_field_display_names(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "conflict_field_display_names", value)

    @property
    @pulumi.getter(name="conflictParserNames")
    def conflict_parser_names(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        A list of parser names with conflicts.
        """
        return pulumi.get(self, "conflict_parser_names")

    @conflict_parser_names.setter
    def conflict_parser_names(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "conflict_parser_names", value)

    @property
    @pulumi.getter(name="conflictSourceNames")
    def conflict_source_names(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        A list of source names with conflicts.
        """
        return pulumi.get(self, "conflict_source_names")

    @conflict_source_names.setter
    def conflict_source_names(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "conflict_source_names", value)

    @property
    @pulumi.getter(name="createdFieldDisplayNames")
    def created_field_display_names(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        An array of created field display names.
        """
        return pulumi.get(self, "created_field_display_names")

    @created_field_display_names.setter
    def created_field_display_names(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "created_field_display_names", value)

    @property
    @pulumi.getter(name="createdParserNames")
    def created_parser_names(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        An array of created parser names.
        """
        return pulumi.get(self, "created_parser_names")

    @created_parser_names.setter
    def created_parser_names(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "created_parser_names", value)

    @property
    @pulumi.getter(name="createdSourceNames")
    def created_source_names(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        An array of created source names.
        """
        return pulumi.get(self, "created_source_names")

    @created_source_names.setter
    def created_source_names(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "created_source_names", value)

    @property
    @pulumi.getter(name="updatedFieldDisplayNames")
    def updated_field_display_names(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        An array of updated field display names.
        """
        return pulumi.get(self, "updated_field_display_names")

    @updated_field_display_names.setter
    def updated_field_display_names(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "updated_field_display_names", value)

    @property
    @pulumi.getter(name="updatedParserNames")
    def updated_parser_names(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        An array of updated parser names.
        """
        return pulumi.get(self, "updated_parser_names")

    @updated_parser_names.setter
    def updated_parser_names(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "updated_parser_names", value)

    @property
    @pulumi.getter(name="updatedSourceNames")
    def updated_source_names(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        An array of updated source names.
        """
        return pulumi.get(self, "updated_source_names")

    @updated_source_names.setter
    def updated_source_names(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "updated_source_names", value)


@pulumi.input_type
class LogAnalyticsObjectCollectionRuleOverrideArgs:
    def __init__(__self__, *,
                 match_type: Optional[pulumi.Input[str]] = None,
                 match_value: Optional[pulumi.Input[str]] = None,
                 property_name: Optional[pulumi.Input[str]] = None,
                 property_value: Optional[pulumi.Input[str]] = None):
        if match_type is not None:
            pulumi.set(__self__, "match_type", match_type)
        if match_value is not None:
            pulumi.set(__self__, "match_value", match_value)
        if property_name is not None:
            pulumi.set(__self__, "property_name", property_name)
        if property_value is not None:
            pulumi.set(__self__, "property_value", property_value)

    @property
    @pulumi.getter(name="matchType")
    def match_type(self) -> Optional[pulumi.Input[str]]:
        return pulumi.get(self, "match_type")

    @match_type.setter
    def match_type(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "match_type", value)

    @property
    @pulumi.getter(name="matchValue")
    def match_value(self) -> Optional[pulumi.Input[str]]:
        return pulumi.get(self, "match_value")

    @match_value.setter
    def match_value(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "match_value", value)

    @property
    @pulumi.getter(name="propertyName")
    def property_name(self) -> Optional[pulumi.Input[str]]:
        return pulumi.get(self, "property_name")

    @property_name.setter
    def property_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "property_name", value)

    @property
    @pulumi.getter(name="propertyValue")
    def property_value(self) -> Optional[pulumi.Input[str]]:
        return pulumi.get(self, "property_value")

    @property_value.setter
    def property_value(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "property_value", value)


@pulumi.input_type
class LogAnalyticsPreferencesManagementItemArgs:
    def __init__(__self__, *,
                 name: Optional[pulumi.Input[str]] = None,
                 value: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] name: The preference name. Currently, only "DEFAULT_HOMEPAGE" is supported.
        :param pulumi.Input[str] value: The preference value.
        """
        if name is not None:
            pulumi.set(__self__, "name", name)
        if value is not None:
            pulumi.set(__self__, "value", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        The preference name. Currently, only "DEFAULT_HOMEPAGE" is supported.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def value(self) -> Optional[pulumi.Input[str]]:
        """
        The preference value.
        """
        return pulumi.get(self, "value")

    @value.setter
    def value(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "value", value)


@pulumi.input_type
class NamespaceScheduledTaskActionArgs:
    def __init__(__self__, *,
                 type: pulumi.Input[str],
                 compartment_id_in_subtree: Optional[pulumi.Input[bool]] = None,
                 data_type: Optional[pulumi.Input[str]] = None,
                 purge_compartment_id: Optional[pulumi.Input[str]] = None,
                 purge_duration: Optional[pulumi.Input[str]] = None,
                 query_string: Optional[pulumi.Input[str]] = None,
                 saved_search_id: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] type: (Updatable) Schedule type discriminator.
        :param pulumi.Input[bool] compartment_id_in_subtree: if true, purge child compartments data
        :param pulumi.Input[str] data_type: the type of the log data to be purged
        :param pulumi.Input[str] purge_compartment_id: the compartment OCID under which the data will be purged
        :param pulumi.Input[str] purge_duration: The duration of data to be retained, which is used to calculate the timeDataEnded when the task fires. The value should be negative. Purge duration in ISO 8601 extended format as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. -P365D (not -P1Y) or -P14D (not -P2W).
        :param pulumi.Input[str] query_string: Purge query string.
        :param pulumi.Input[str] saved_search_id: The ManagementSavedSearch id [OCID] to be accelerated.
        """
        pulumi.set(__self__, "type", type)
        if compartment_id_in_subtree is not None:
            pulumi.set(__self__, "compartment_id_in_subtree", compartment_id_in_subtree)
        if data_type is not None:
            pulumi.set(__self__, "data_type", data_type)
        if purge_compartment_id is not None:
            pulumi.set(__self__, "purge_compartment_id", purge_compartment_id)
        if purge_duration is not None:
            pulumi.set(__self__, "purge_duration", purge_duration)
        if query_string is not None:
            pulumi.set(__self__, "query_string", query_string)
        if saved_search_id is not None:
            pulumi.set(__self__, "saved_search_id", saved_search_id)

    @property
    @pulumi.getter
    def type(self) -> pulumi.Input[str]:
        """
        (Updatable) Schedule type discriminator.
        """
        return pulumi.get(self, "type")

    @type.setter
    def type(self, value: pulumi.Input[str]):
        pulumi.set(self, "type", value)

    @property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[pulumi.Input[bool]]:
        """
        if true, purge child compartments data
        """
        return pulumi.get(self, "compartment_id_in_subtree")

    @compartment_id_in_subtree.setter
    def compartment_id_in_subtree(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "compartment_id_in_subtree", value)

    @property
    @pulumi.getter(name="dataType")
    def data_type(self) -> Optional[pulumi.Input[str]]:
        """
        the type of the log data to be purged
        """
        return pulumi.get(self, "data_type")

    @data_type.setter
    def data_type(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "data_type", value)

    @property
    @pulumi.getter(name="purgeCompartmentId")
    def purge_compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        the compartment OCID under which the data will be purged
        """
        return pulumi.get(self, "purge_compartment_id")

    @purge_compartment_id.setter
    def purge_compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "purge_compartment_id", value)

    @property
    @pulumi.getter(name="purgeDuration")
    def purge_duration(self) -> Optional[pulumi.Input[str]]:
        """
        The duration of data to be retained, which is used to calculate the timeDataEnded when the task fires. The value should be negative. Purge duration in ISO 8601 extended format as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. -P365D (not -P1Y) or -P14D (not -P2W).
        """
        return pulumi.get(self, "purge_duration")

    @purge_duration.setter
    def purge_duration(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "purge_duration", value)

    @property
    @pulumi.getter(name="queryString")
    def query_string(self) -> Optional[pulumi.Input[str]]:
        """
        Purge query string.
        """
        return pulumi.get(self, "query_string")

    @query_string.setter
    def query_string(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "query_string", value)

    @property
    @pulumi.getter(name="savedSearchId")
    def saved_search_id(self) -> Optional[pulumi.Input[str]]:
        """
        The ManagementSavedSearch id [OCID] to be accelerated.
        """
        return pulumi.get(self, "saved_search_id")

    @saved_search_id.setter
    def saved_search_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "saved_search_id", value)


@pulumi.input_type
class NamespaceScheduledTaskSchedulesArgs:
    def __init__(__self__, *,
                 schedules: pulumi.Input[Sequence[pulumi.Input['NamespaceScheduledTaskSchedulesScheduleArgs']]]):
        pulumi.set(__self__, "schedules", schedules)

    @property
    @pulumi.getter
    def schedules(self) -> pulumi.Input[Sequence[pulumi.Input['NamespaceScheduledTaskSchedulesScheduleArgs']]]:
        return pulumi.get(self, "schedules")

    @schedules.setter
    def schedules(self, value: pulumi.Input[Sequence[pulumi.Input['NamespaceScheduledTaskSchedulesScheduleArgs']]]):
        pulumi.set(self, "schedules", value)


@pulumi.input_type
class NamespaceScheduledTaskSchedulesScheduleArgs:
    def __init__(__self__, *,
                 type: pulumi.Input[str],
                 expression: Optional[pulumi.Input[str]] = None,
                 misfire_policy: Optional[pulumi.Input[str]] = None,
                 recurring_interval: Optional[pulumi.Input[str]] = None,
                 repeat_count: Optional[pulumi.Input[int]] = None,
                 time_zone: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] type: (Updatable) Schedule type discriminator.
        :param pulumi.Input[str] expression: (Updatable) Value in cron format.
        :param pulumi.Input[str] misfire_policy: (Updatable) Schedule misfire retry policy.
        :param pulumi.Input[str] recurring_interval: (Updatable) Recurring interval in ISO 8601 extended format as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. P14D (not P2W). The value must be at least 5 minutes (PT5M) and at most 3 weeks (P21D or PT30240M).
        :param pulumi.Input[int] repeat_count: (Updatable) Number of times (0-based) to execute until auto-stop. Default value -1 will execute indefinitely. Value 0 will execute once.
        :param pulumi.Input[str] time_zone: (Updatable) Time zone, by default UTC.
        """
        pulumi.set(__self__, "type", type)
        if expression is not None:
            pulumi.set(__self__, "expression", expression)
        if misfire_policy is not None:
            pulumi.set(__self__, "misfire_policy", misfire_policy)
        if recurring_interval is not None:
            pulumi.set(__self__, "recurring_interval", recurring_interval)
        if repeat_count is not None:
            pulumi.set(__self__, "repeat_count", repeat_count)
        if time_zone is not None:
            pulumi.set(__self__, "time_zone", time_zone)

    @property
    @pulumi.getter
    def type(self) -> pulumi.Input[str]:
        """
        (Updatable) Schedule type discriminator.
        """
        return pulumi.get(self, "type")

    @type.setter
    def type(self, value: pulumi.Input[str]):
        pulumi.set(self, "type", value)

    @property
    @pulumi.getter
    def expression(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Value in cron format.
        """
        return pulumi.get(self, "expression")

    @expression.setter
    def expression(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "expression", value)

    @property
    @pulumi.getter(name="misfirePolicy")
    def misfire_policy(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Schedule misfire retry policy.
        """
        return pulumi.get(self, "misfire_policy")

    @misfire_policy.setter
    def misfire_policy(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "misfire_policy", value)

    @property
    @pulumi.getter(name="recurringInterval")
    def recurring_interval(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Recurring interval in ISO 8601 extended format as described in https://en.wikipedia.org/wiki/ISO_8601#Durations. The largest supported unit is D, e.g. P14D (not P2W). The value must be at least 5 minutes (PT5M) and at most 3 weeks (P21D or PT30240M).
        """
        return pulumi.get(self, "recurring_interval")

    @recurring_interval.setter
    def recurring_interval(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "recurring_interval", value)

    @property
    @pulumi.getter(name="repeatCount")
    def repeat_count(self) -> Optional[pulumi.Input[int]]:
        """
        (Updatable) Number of times (0-based) to execute until auto-stop. Default value -1 will execute indefinitely. Value 0 will execute once.
        """
        return pulumi.get(self, "repeat_count")

    @repeat_count.setter
    def repeat_count(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "repeat_count", value)

    @property
    @pulumi.getter(name="timeZone")
    def time_zone(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Time zone, by default UTC.
        """
        return pulumi.get(self, "time_zone")

    @time_zone.setter
    def time_zone(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_zone", value)


@pulumi.input_type
class GetLogAnalyticsEntitiesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: A filter to return only log analytics entities whose name matches the entire name given. The match is case-insensitive.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A filter to return only log analytics entities whose name matches the entire name given. The match is case-insensitive.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetLogAnalyticsLogGroupsFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetLogAnalyticsObjectCollectionRulesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: A filter to return rules only matching with this name.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A filter to return rules only matching with this name.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetNamespaceScheduledTasksFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


@pulumi.input_type
class GetNamespacesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: str):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[str]):
        pulumi.set(self, "values", value)

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[bool]):
        pulumi.set(self, "regex", value)


