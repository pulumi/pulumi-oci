# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'AnalyticsInstanceCapacityArgs',
    'AnalyticsInstanceNetworkEndpointDetailsArgs',
    'AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnArgs',
    'AnalyticsInstancePrivateAccessChannelPrivateSourceDnsZoneArgs',
    'AnalyticsInstancePrivateAccessChannelPrivateSourceScanHostArgs',
    'GetAnalyticsInstancesFilterArgs',
]

@pulumi.input_type
class AnalyticsInstanceCapacityArgs:
    def __init__(__self__, *,
                 capacity_type: pulumi.Input[str],
                 capacity_value: pulumi.Input[int]):
        """
        :param pulumi.Input[str] capacity_type: The capacity model to use.
        :param pulumi.Input[int] capacity_value: (Updatable) The capacity value selected (OLPU count, number of users, ...etc...). This parameter affects the number of CPUs, amount of memory or other resources allocated to the instance.
        """
        pulumi.set(__self__, "capacity_type", capacity_type)
        pulumi.set(__self__, "capacity_value", capacity_value)

    @property
    @pulumi.getter(name="capacityType")
    def capacity_type(self) -> pulumi.Input[str]:
        """
        The capacity model to use.
        """
        return pulumi.get(self, "capacity_type")

    @capacity_type.setter
    def capacity_type(self, value: pulumi.Input[str]):
        pulumi.set(self, "capacity_type", value)

    @property
    @pulumi.getter(name="capacityValue")
    def capacity_value(self) -> pulumi.Input[int]:
        """
        (Updatable) The capacity value selected (OLPU count, number of users, ...etc...). This parameter affects the number of CPUs, amount of memory or other resources allocated to the instance.
        """
        return pulumi.get(self, "capacity_value")

    @capacity_value.setter
    def capacity_value(self, value: pulumi.Input[int]):
        pulumi.set(self, "capacity_value", value)


@pulumi.input_type
class AnalyticsInstanceNetworkEndpointDetailsArgs:
    def __init__(__self__, *,
                 network_endpoint_type: pulumi.Input[str],
                 network_security_group_ids: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 subnet_id: Optional[pulumi.Input[str]] = None,
                 vcn_id: Optional[pulumi.Input[str]] = None,
                 whitelisted_ips: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 whitelisted_services: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 whitelisted_vcns: Optional[pulumi.Input[Sequence[pulumi.Input['AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnArgs']]]] = None):
        """
        :param pulumi.Input[str] network_endpoint_type: The type of network endpoint.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] network_security_group_ids: Network Security Group OCIDs for an Analytics instance.
        :param pulumi.Input[str] subnet_id: The subnet OCID for the private endpoint.
        :param pulumi.Input[str] vcn_id: The VCN OCID for the private endpoint.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] whitelisted_ips: Source IP addresses or IP address ranges in ingress rules.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] whitelisted_services: Oracle Cloud Services that are allowed to access this Analytics instance.
        :param pulumi.Input[Sequence[pulumi.Input['AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnArgs']]] whitelisted_vcns: Virtual Cloud Networks allowed to access this network endpoint.
        """
        pulumi.set(__self__, "network_endpoint_type", network_endpoint_type)
        if network_security_group_ids is not None:
            pulumi.set(__self__, "network_security_group_ids", network_security_group_ids)
        if subnet_id is not None:
            pulumi.set(__self__, "subnet_id", subnet_id)
        if vcn_id is not None:
            pulumi.set(__self__, "vcn_id", vcn_id)
        if whitelisted_ips is not None:
            pulumi.set(__self__, "whitelisted_ips", whitelisted_ips)
        if whitelisted_services is not None:
            pulumi.set(__self__, "whitelisted_services", whitelisted_services)
        if whitelisted_vcns is not None:
            pulumi.set(__self__, "whitelisted_vcns", whitelisted_vcns)

    @property
    @pulumi.getter(name="networkEndpointType")
    def network_endpoint_type(self) -> pulumi.Input[str]:
        """
        The type of network endpoint.
        """
        return pulumi.get(self, "network_endpoint_type")

    @network_endpoint_type.setter
    def network_endpoint_type(self, value: pulumi.Input[str]):
        pulumi.set(self, "network_endpoint_type", value)

    @property
    @pulumi.getter(name="networkSecurityGroupIds")
    def network_security_group_ids(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        Network Security Group OCIDs for an Analytics instance.
        """
        return pulumi.get(self, "network_security_group_ids")

    @network_security_group_ids.setter
    def network_security_group_ids(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "network_security_group_ids", value)

    @property
    @pulumi.getter(name="subnetId")
    def subnet_id(self) -> Optional[pulumi.Input[str]]:
        """
        The subnet OCID for the private endpoint.
        """
        return pulumi.get(self, "subnet_id")

    @subnet_id.setter
    def subnet_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "subnet_id", value)

    @property
    @pulumi.getter(name="vcnId")
    def vcn_id(self) -> Optional[pulumi.Input[str]]:
        """
        The VCN OCID for the private endpoint.
        """
        return pulumi.get(self, "vcn_id")

    @vcn_id.setter
    def vcn_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "vcn_id", value)

    @property
    @pulumi.getter(name="whitelistedIps")
    def whitelisted_ips(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        Source IP addresses or IP address ranges in ingress rules.
        """
        return pulumi.get(self, "whitelisted_ips")

    @whitelisted_ips.setter
    def whitelisted_ips(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "whitelisted_ips", value)

    @property
    @pulumi.getter(name="whitelistedServices")
    def whitelisted_services(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        Oracle Cloud Services that are allowed to access this Analytics instance.
        """
        return pulumi.get(self, "whitelisted_services")

    @whitelisted_services.setter
    def whitelisted_services(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "whitelisted_services", value)

    @property
    @pulumi.getter(name="whitelistedVcns")
    def whitelisted_vcns(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnArgs']]]]:
        """
        Virtual Cloud Networks allowed to access this network endpoint.
        """
        return pulumi.get(self, "whitelisted_vcns")

    @whitelisted_vcns.setter
    def whitelisted_vcns(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnArgs']]]]):
        pulumi.set(self, "whitelisted_vcns", value)


@pulumi.input_type
class AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnArgs:
    def __init__(__self__, *,
                 id: Optional[pulumi.Input[str]] = None,
                 whitelisted_ips: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None):
        """
        :param pulumi.Input[str] id: The Virtual Cloud Network OCID.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] whitelisted_ips: Source IP addresses or IP address ranges in ingress rules.
        """
        if id is not None:
            pulumi.set(__self__, "id", id)
        if whitelisted_ips is not None:
            pulumi.set(__self__, "whitelisted_ips", whitelisted_ips)

    @property
    @pulumi.getter
    def id(self) -> Optional[pulumi.Input[str]]:
        """
        The Virtual Cloud Network OCID.
        """
        return pulumi.get(self, "id")

    @id.setter
    def id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "id", value)

    @property
    @pulumi.getter(name="whitelistedIps")
    def whitelisted_ips(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        Source IP addresses or IP address ranges in ingress rules.
        """
        return pulumi.get(self, "whitelisted_ips")

    @whitelisted_ips.setter
    def whitelisted_ips(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "whitelisted_ips", value)


@pulumi.input_type
class AnalyticsInstancePrivateAccessChannelPrivateSourceDnsZoneArgs:
    def __init__(__self__, *,
                 dns_zone: pulumi.Input[str],
                 description: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] dns_zone: (Updatable) Private Source DNS Zone. Ex: example-vcn.oraclevcn.com, corp.example.com.
        :param pulumi.Input[str] description: (Updatable) Description of private source scan host zone.
        """
        pulumi.set(__self__, "dns_zone", dns_zone)
        if description is not None:
            pulumi.set(__self__, "description", description)

    @property
    @pulumi.getter(name="dnsZone")
    def dns_zone(self) -> pulumi.Input[str]:
        """
        (Updatable) Private Source DNS Zone. Ex: example-vcn.oraclevcn.com, corp.example.com.
        """
        return pulumi.get(self, "dns_zone")

    @dns_zone.setter
    def dns_zone(self, value: pulumi.Input[str]):
        pulumi.set(self, "dns_zone", value)

    @property
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Description of private source scan host zone.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "description", value)


@pulumi.input_type
class AnalyticsInstancePrivateAccessChannelPrivateSourceScanHostArgs:
    def __init__(__self__, *,
                 scan_hostname: pulumi.Input[str],
                 scan_port: pulumi.Input[int],
                 description: Optional[pulumi.Input[str]] = None):
        """
        :param pulumi.Input[str] scan_hostname: (Updatable) Private Source Scan hostname. Ex: db01-scan.corp.example.com, prd-db01-scan.mycompany.com.
        :param pulumi.Input[int] scan_port: (Updatable) Private Source Scan host port. This is the source port where SCAN protocol will get connected (e.g. 1521).
        :param pulumi.Input[str] description: (Updatable) Description of private source scan host zone.
        """
        pulumi.set(__self__, "scan_hostname", scan_hostname)
        pulumi.set(__self__, "scan_port", scan_port)
        if description is not None:
            pulumi.set(__self__, "description", description)

    @property
    @pulumi.getter(name="scanHostname")
    def scan_hostname(self) -> pulumi.Input[str]:
        """
        (Updatable) Private Source Scan hostname. Ex: db01-scan.corp.example.com, prd-db01-scan.mycompany.com.
        """
        return pulumi.get(self, "scan_hostname")

    @scan_hostname.setter
    def scan_hostname(self, value: pulumi.Input[str]):
        pulumi.set(self, "scan_hostname", value)

    @property
    @pulumi.getter(name="scanPort")
    def scan_port(self) -> pulumi.Input[int]:
        """
        (Updatable) Private Source Scan host port. This is the source port where SCAN protocol will get connected (e.g. 1521).
        """
        return pulumi.get(self, "scan_port")

    @scan_port.setter
    def scan_port(self, value: pulumi.Input[int]):
        pulumi.set(self, "scan_port", value)

    @property
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Description of private source scan host zone.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "description", value)


@pulumi.input_type
class GetAnalyticsInstancesFilterArgs:
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: A filter to return only resources that match the given name exactly.
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        A filter to return only resources that match the given name exactly.
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

