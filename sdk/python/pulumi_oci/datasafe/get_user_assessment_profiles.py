# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetUserAssessmentProfilesResult',
    'AwaitableGetUserAssessmentProfilesResult',
    'get_user_assessment_profiles',
    'get_user_assessment_profiles_output',
]

@pulumi.output_type
class GetUserAssessmentProfilesResult:
    """
    A collection of values returned by getUserAssessmentProfiles.
    """
    def __init__(__self__, access_level=None, compartment_id=None, compartment_id_in_subtree=None, failed_login_attempts_greater_than_or_equal=None, failed_login_attempts_less_than=None, filters=None, id=None, inactive_account_time_greater_than_or_equal=None, inactive_account_time_less_than=None, is_user_created=None, password_lock_time_greater_than_or_equal=None, password_lock_time_less_than=None, password_verification_function=None, profile_name=None, profiles=None, sessions_per_user_greater_than_or_equal=None, sessions_per_user_less_than=None, target_id=None, user_assessment_id=None, user_count_greater_than_or_equal=None, user_count_less_than=None):
        if access_level and not isinstance(access_level, str):
            raise TypeError("Expected argument 'access_level' to be a str")
        pulumi.set(__self__, "access_level", access_level)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compartment_id_in_subtree and not isinstance(compartment_id_in_subtree, bool):
            raise TypeError("Expected argument 'compartment_id_in_subtree' to be a bool")
        pulumi.set(__self__, "compartment_id_in_subtree", compartment_id_in_subtree)
        if failed_login_attempts_greater_than_or_equal and not isinstance(failed_login_attempts_greater_than_or_equal, str):
            raise TypeError("Expected argument 'failed_login_attempts_greater_than_or_equal' to be a str")
        pulumi.set(__self__, "failed_login_attempts_greater_than_or_equal", failed_login_attempts_greater_than_or_equal)
        if failed_login_attempts_less_than and not isinstance(failed_login_attempts_less_than, str):
            raise TypeError("Expected argument 'failed_login_attempts_less_than' to be a str")
        pulumi.set(__self__, "failed_login_attempts_less_than", failed_login_attempts_less_than)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if inactive_account_time_greater_than_or_equal and not isinstance(inactive_account_time_greater_than_or_equal, str):
            raise TypeError("Expected argument 'inactive_account_time_greater_than_or_equal' to be a str")
        pulumi.set(__self__, "inactive_account_time_greater_than_or_equal", inactive_account_time_greater_than_or_equal)
        if inactive_account_time_less_than and not isinstance(inactive_account_time_less_than, str):
            raise TypeError("Expected argument 'inactive_account_time_less_than' to be a str")
        pulumi.set(__self__, "inactive_account_time_less_than", inactive_account_time_less_than)
        if is_user_created and not isinstance(is_user_created, bool):
            raise TypeError("Expected argument 'is_user_created' to be a bool")
        pulumi.set(__self__, "is_user_created", is_user_created)
        if password_lock_time_greater_than_or_equal and not isinstance(password_lock_time_greater_than_or_equal, str):
            raise TypeError("Expected argument 'password_lock_time_greater_than_or_equal' to be a str")
        pulumi.set(__self__, "password_lock_time_greater_than_or_equal", password_lock_time_greater_than_or_equal)
        if password_lock_time_less_than and not isinstance(password_lock_time_less_than, str):
            raise TypeError("Expected argument 'password_lock_time_less_than' to be a str")
        pulumi.set(__self__, "password_lock_time_less_than", password_lock_time_less_than)
        if password_verification_function and not isinstance(password_verification_function, str):
            raise TypeError("Expected argument 'password_verification_function' to be a str")
        pulumi.set(__self__, "password_verification_function", password_verification_function)
        if profile_name and not isinstance(profile_name, str):
            raise TypeError("Expected argument 'profile_name' to be a str")
        pulumi.set(__self__, "profile_name", profile_name)
        if profiles and not isinstance(profiles, list):
            raise TypeError("Expected argument 'profiles' to be a list")
        pulumi.set(__self__, "profiles", profiles)
        if sessions_per_user_greater_than_or_equal and not isinstance(sessions_per_user_greater_than_or_equal, str):
            raise TypeError("Expected argument 'sessions_per_user_greater_than_or_equal' to be a str")
        pulumi.set(__self__, "sessions_per_user_greater_than_or_equal", sessions_per_user_greater_than_or_equal)
        if sessions_per_user_less_than and not isinstance(sessions_per_user_less_than, str):
            raise TypeError("Expected argument 'sessions_per_user_less_than' to be a str")
        pulumi.set(__self__, "sessions_per_user_less_than", sessions_per_user_less_than)
        if target_id and not isinstance(target_id, str):
            raise TypeError("Expected argument 'target_id' to be a str")
        pulumi.set(__self__, "target_id", target_id)
        if user_assessment_id and not isinstance(user_assessment_id, str):
            raise TypeError("Expected argument 'user_assessment_id' to be a str")
        pulumi.set(__self__, "user_assessment_id", user_assessment_id)
        if user_count_greater_than_or_equal and not isinstance(user_count_greater_than_or_equal, str):
            raise TypeError("Expected argument 'user_count_greater_than_or_equal' to be a str")
        pulumi.set(__self__, "user_count_greater_than_or_equal", user_count_greater_than_or_equal)
        if user_count_less_than and not isinstance(user_count_less_than, str):
            raise TypeError("Expected argument 'user_count_less_than' to be a str")
        pulumi.set(__self__, "user_count_less_than", user_count_less_than)

    @property
    @pulumi.getter(name="accessLevel")
    def access_level(self) -> Optional[str]:
        return pulumi.get(self, "access_level")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment that contains the user assessment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[bool]:
        return pulumi.get(self, "compartment_id_in_subtree")

    @property
    @pulumi.getter(name="failedLoginAttemptsGreaterThanOrEqual")
    def failed_login_attempts_greater_than_or_equal(self) -> Optional[str]:
        return pulumi.get(self, "failed_login_attempts_greater_than_or_equal")

    @property
    @pulumi.getter(name="failedLoginAttemptsLessThan")
    def failed_login_attempts_less_than(self) -> Optional[str]:
        return pulumi.get(self, "failed_login_attempts_less_than")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetUserAssessmentProfilesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="inactiveAccountTimeGreaterThanOrEqual")
    def inactive_account_time_greater_than_or_equal(self) -> Optional[str]:
        return pulumi.get(self, "inactive_account_time_greater_than_or_equal")

    @property
    @pulumi.getter(name="inactiveAccountTimeLessThan")
    def inactive_account_time_less_than(self) -> Optional[str]:
        return pulumi.get(self, "inactive_account_time_less_than")

    @property
    @pulumi.getter(name="isUserCreated")
    def is_user_created(self) -> Optional[bool]:
        """
        Represents if the profile is created by user.
        """
        return pulumi.get(self, "is_user_created")

    @property
    @pulumi.getter(name="passwordLockTimeGreaterThanOrEqual")
    def password_lock_time_greater_than_or_equal(self) -> Optional[str]:
        return pulumi.get(self, "password_lock_time_greater_than_or_equal")

    @property
    @pulumi.getter(name="passwordLockTimeLessThan")
    def password_lock_time_less_than(self) -> Optional[str]:
        return pulumi.get(self, "password_lock_time_less_than")

    @property
    @pulumi.getter(name="passwordVerificationFunction")
    def password_verification_function(self) -> Optional[str]:
        """
        Name of the PL/SQL that can be used for password verification.
        """
        return pulumi.get(self, "password_verification_function")

    @property
    @pulumi.getter(name="profileName")
    def profile_name(self) -> Optional[str]:
        """
        The name of the profile.
        """
        return pulumi.get(self, "profile_name")

    @property
    @pulumi.getter
    def profiles(self) -> Sequence['outputs.GetUserAssessmentProfilesProfileResult']:
        """
        The list of profiles.
        """
        return pulumi.get(self, "profiles")

    @property
    @pulumi.getter(name="sessionsPerUserGreaterThanOrEqual")
    def sessions_per_user_greater_than_or_equal(self) -> Optional[str]:
        return pulumi.get(self, "sessions_per_user_greater_than_or_equal")

    @property
    @pulumi.getter(name="sessionsPerUserLessThan")
    def sessions_per_user_less_than(self) -> Optional[str]:
        return pulumi.get(self, "sessions_per_user_less_than")

    @property
    @pulumi.getter(name="targetId")
    def target_id(self) -> Optional[str]:
        """
        The OCID of the target database.
        """
        return pulumi.get(self, "target_id")

    @property
    @pulumi.getter(name="userAssessmentId")
    def user_assessment_id(self) -> str:
        """
        The OCID of the latest user assessment corresponding to the target under consideration. A compartment  type assessment can also be passed to profiles from all the targets from the corresponding compartment.
        """
        return pulumi.get(self, "user_assessment_id")

    @property
    @pulumi.getter(name="userCountGreaterThanOrEqual")
    def user_count_greater_than_or_equal(self) -> Optional[str]:
        return pulumi.get(self, "user_count_greater_than_or_equal")

    @property
    @pulumi.getter(name="userCountLessThan")
    def user_count_less_than(self) -> Optional[str]:
        return pulumi.get(self, "user_count_less_than")


class AwaitableGetUserAssessmentProfilesResult(GetUserAssessmentProfilesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetUserAssessmentProfilesResult(
            access_level=self.access_level,
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            failed_login_attempts_greater_than_or_equal=self.failed_login_attempts_greater_than_or_equal,
            failed_login_attempts_less_than=self.failed_login_attempts_less_than,
            filters=self.filters,
            id=self.id,
            inactive_account_time_greater_than_or_equal=self.inactive_account_time_greater_than_or_equal,
            inactive_account_time_less_than=self.inactive_account_time_less_than,
            is_user_created=self.is_user_created,
            password_lock_time_greater_than_or_equal=self.password_lock_time_greater_than_or_equal,
            password_lock_time_less_than=self.password_lock_time_less_than,
            password_verification_function=self.password_verification_function,
            profile_name=self.profile_name,
            profiles=self.profiles,
            sessions_per_user_greater_than_or_equal=self.sessions_per_user_greater_than_or_equal,
            sessions_per_user_less_than=self.sessions_per_user_less_than,
            target_id=self.target_id,
            user_assessment_id=self.user_assessment_id,
            user_count_greater_than_or_equal=self.user_count_greater_than_or_equal,
            user_count_less_than=self.user_count_less_than)


def get_user_assessment_profiles(access_level: Optional[str] = None,
                                 compartment_id: Optional[str] = None,
                                 compartment_id_in_subtree: Optional[bool] = None,
                                 failed_login_attempts_greater_than_or_equal: Optional[str] = None,
                                 failed_login_attempts_less_than: Optional[str] = None,
                                 filters: Optional[Sequence[pulumi.InputType['GetUserAssessmentProfilesFilterArgs']]] = None,
                                 inactive_account_time_greater_than_or_equal: Optional[str] = None,
                                 inactive_account_time_less_than: Optional[str] = None,
                                 is_user_created: Optional[bool] = None,
                                 password_lock_time_greater_than_or_equal: Optional[str] = None,
                                 password_lock_time_less_than: Optional[str] = None,
                                 password_verification_function: Optional[str] = None,
                                 profile_name: Optional[str] = None,
                                 sessions_per_user_greater_than_or_equal: Optional[str] = None,
                                 sessions_per_user_less_than: Optional[str] = None,
                                 target_id: Optional[str] = None,
                                 user_assessment_id: Optional[str] = None,
                                 user_count_greater_than_or_equal: Optional[str] = None,
                                 user_count_less_than: Optional[str] = None,
                                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetUserAssessmentProfilesResult:
    """
    This data source provides the list of User Assessment Profiles in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of user profiles containing the profile details along with the target id and user counts.

    The ListProfiles operation returns only the profiles belonging to a certain target. If compartment type user assessment
    id is provided, then profile information for all the targets belonging to the pertaining compartment is returned.
    The list does not include any subcompartments of the compartment under consideration.

    The parameter 'accessLevel' specifies whether to return only those compartments for which the requestor has
    INSPECT permissions on at least one resource directly or indirectly (ACCESSIBLE) (the resource can be in a
    subcompartment) or to return Not Authorized if Principal doesn't have access to even one of the child compartments.
    This is valid only when 'compartmentIdInSubtree' is set to 'true'.

    The parameter 'compartmentIdInSubtree' applies when you perform ListUserProfiles on the 'compartmentId' belonging
    to the assessmentId passed and when it is set to true, the entire hierarchy of compartments can be returned.
    To get a full list of all compartments and subcompartments in the tenancy (root compartment), set the parameter
    'compartmentIdInSubtree' to true and 'accessLevel' to ACCESSIBLE.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_user_assessment_profiles = oci.DataSafe.get_user_assessment_profiles(compartment_id=var["compartment_id"],
        user_assessment_id=oci_data_safe_user_assessment["test_user_assessment"]["id"],
        access_level=var["user_assessment_profile_access_level"],
        compartment_id_in_subtree=var["user_assessment_profile_compartment_id_in_subtree"],
        failed_login_attempts_greater_than_or_equal=var["user_assessment_profile_failed_login_attempts_greater_than_or_equal"],
        failed_login_attempts_less_than=var["user_assessment_profile_failed_login_attempts_less_than"],
        inactive_account_time_greater_than_or_equal=var["user_assessment_profile_inactive_account_time_greater_than_or_equal"],
        inactive_account_time_less_than=var["user_assessment_profile_inactive_account_time_less_than"],
        is_user_created=var["user_assessment_profile_is_user_created"],
        password_lock_time_greater_than_or_equal=var["user_assessment_profile_password_lock_time_greater_than_or_equal"],
        password_lock_time_less_than=var["user_assessment_profile_password_lock_time_less_than"],
        password_verification_function=var["user_assessment_profile_password_verification_function"],
        profile_name=oci_optimizer_profile["test_profile"]["name"],
        sessions_per_user_greater_than_or_equal=var["user_assessment_profile_sessions_per_user_greater_than_or_equal"],
        sessions_per_user_less_than=var["user_assessment_profile_sessions_per_user_less_than"],
        target_id=oci_cloud_guard_target["test_target"]["id"],
        user_count_greater_than_or_equal=var["user_assessment_profile_user_count_greater_than_or_equal"],
        user_count_less_than=var["user_assessment_profile_user_count_less_than"])
    ```


    :param str access_level: Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
    :param str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param str failed_login_attempts_greater_than_or_equal: An optional filter to return the profiles having allow failed login attempts number greater than or equal to the provided value. String value is used for accommodating the "UNLIMITED" and "DEFAULT" values.
    :param str failed_login_attempts_less_than: An optional filter to return the profiles having failed login attempts number less than the provided value. String value is used for accommodating the "UNLIMITED" and "DEFAULT" values.
    :param str inactive_account_time_greater_than_or_equal: An optional filter to return the profiles allowing inactive account time in days greater than or equal to the provided value. String value is used for accommodating the "UNLIMITED" and "DEFAULT" values.
    :param str inactive_account_time_less_than: An optional filter to return the profiles  allowing inactive account time in days less than the provided value. String value is used for accommodating the "UNLIMITED" and "DEFAULT" values.
    :param bool is_user_created: An optional filter to return the user created profiles.
    :param str password_lock_time_greater_than_or_equal: An optional filter to return the profiles having password lock number greater than or equal to the provided value. String value is used for accommodating the "UNLIMITED" and "DEFAULT" values.
    :param str password_lock_time_less_than: An optional filter to return the profiles having password lock number less than the provided value. String value is used for accommodating the "UNLIMITED" and "DEFAULT" values.
    :param str password_verification_function: An optional filter to filter the profiles based on password verification function.
    :param str profile_name: A filter to return only items that match the specified profile name.
    :param str sessions_per_user_greater_than_or_equal: An optional filter to return the profiles permitting the user to spawn multiple sessions having count. greater than or equal to the provided value. String value is used for accommodating the "UNLIMITED" and "DEFAULT" values.
    :param str sessions_per_user_less_than: An optional filter to return the profiles permitting the user to spawn multiple sessions having count less than the provided value. String value is used for accommodating the "UNLIMITED" and "DEFAULT" values.
    :param str target_id: A filter to return only items related to a specific target OCID.
    :param str user_assessment_id: The OCID of the user assessment.
    :param str user_count_greater_than_or_equal: An optional filter to return the profiles having user count greater than or equal to the provided value.
    :param str user_count_less_than: An optional filter to return the profiles having user count less than the provided value.
    """
    __args__ = dict()
    __args__['accessLevel'] = access_level
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['failedLoginAttemptsGreaterThanOrEqual'] = failed_login_attempts_greater_than_or_equal
    __args__['failedLoginAttemptsLessThan'] = failed_login_attempts_less_than
    __args__['filters'] = filters
    __args__['inactiveAccountTimeGreaterThanOrEqual'] = inactive_account_time_greater_than_or_equal
    __args__['inactiveAccountTimeLessThan'] = inactive_account_time_less_than
    __args__['isUserCreated'] = is_user_created
    __args__['passwordLockTimeGreaterThanOrEqual'] = password_lock_time_greater_than_or_equal
    __args__['passwordLockTimeLessThan'] = password_lock_time_less_than
    __args__['passwordVerificationFunction'] = password_verification_function
    __args__['profileName'] = profile_name
    __args__['sessionsPerUserGreaterThanOrEqual'] = sessions_per_user_greater_than_or_equal
    __args__['sessionsPerUserLessThan'] = sessions_per_user_less_than
    __args__['targetId'] = target_id
    __args__['userAssessmentId'] = user_assessment_id
    __args__['userCountGreaterThanOrEqual'] = user_count_greater_than_or_equal
    __args__['userCountLessThan'] = user_count_less_than
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getUserAssessmentProfiles:getUserAssessmentProfiles', __args__, opts=opts, typ=GetUserAssessmentProfilesResult).value

    return AwaitableGetUserAssessmentProfilesResult(
        access_level=__ret__.access_level,
        compartment_id=__ret__.compartment_id,
        compartment_id_in_subtree=__ret__.compartment_id_in_subtree,
        failed_login_attempts_greater_than_or_equal=__ret__.failed_login_attempts_greater_than_or_equal,
        failed_login_attempts_less_than=__ret__.failed_login_attempts_less_than,
        filters=__ret__.filters,
        id=__ret__.id,
        inactive_account_time_greater_than_or_equal=__ret__.inactive_account_time_greater_than_or_equal,
        inactive_account_time_less_than=__ret__.inactive_account_time_less_than,
        is_user_created=__ret__.is_user_created,
        password_lock_time_greater_than_or_equal=__ret__.password_lock_time_greater_than_or_equal,
        password_lock_time_less_than=__ret__.password_lock_time_less_than,
        password_verification_function=__ret__.password_verification_function,
        profile_name=__ret__.profile_name,
        profiles=__ret__.profiles,
        sessions_per_user_greater_than_or_equal=__ret__.sessions_per_user_greater_than_or_equal,
        sessions_per_user_less_than=__ret__.sessions_per_user_less_than,
        target_id=__ret__.target_id,
        user_assessment_id=__ret__.user_assessment_id,
        user_count_greater_than_or_equal=__ret__.user_count_greater_than_or_equal,
        user_count_less_than=__ret__.user_count_less_than)


@_utilities.lift_output_func(get_user_assessment_profiles)
def get_user_assessment_profiles_output(access_level: Optional[pulumi.Input[Optional[str]]] = None,
                                        compartment_id: Optional[pulumi.Input[str]] = None,
                                        compartment_id_in_subtree: Optional[pulumi.Input[Optional[bool]]] = None,
                                        failed_login_attempts_greater_than_or_equal: Optional[pulumi.Input[Optional[str]]] = None,
                                        failed_login_attempts_less_than: Optional[pulumi.Input[Optional[str]]] = None,
                                        filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetUserAssessmentProfilesFilterArgs']]]]] = None,
                                        inactive_account_time_greater_than_or_equal: Optional[pulumi.Input[Optional[str]]] = None,
                                        inactive_account_time_less_than: Optional[pulumi.Input[Optional[str]]] = None,
                                        is_user_created: Optional[pulumi.Input[Optional[bool]]] = None,
                                        password_lock_time_greater_than_or_equal: Optional[pulumi.Input[Optional[str]]] = None,
                                        password_lock_time_less_than: Optional[pulumi.Input[Optional[str]]] = None,
                                        password_verification_function: Optional[pulumi.Input[Optional[str]]] = None,
                                        profile_name: Optional[pulumi.Input[Optional[str]]] = None,
                                        sessions_per_user_greater_than_or_equal: Optional[pulumi.Input[Optional[str]]] = None,
                                        sessions_per_user_less_than: Optional[pulumi.Input[Optional[str]]] = None,
                                        target_id: Optional[pulumi.Input[Optional[str]]] = None,
                                        user_assessment_id: Optional[pulumi.Input[str]] = None,
                                        user_count_greater_than_or_equal: Optional[pulumi.Input[Optional[str]]] = None,
                                        user_count_less_than: Optional[pulumi.Input[Optional[str]]] = None,
                                        opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetUserAssessmentProfilesResult]:
    """
    This data source provides the list of User Assessment Profiles in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of user profiles containing the profile details along with the target id and user counts.

    The ListProfiles operation returns only the profiles belonging to a certain target. If compartment type user assessment
    id is provided, then profile information for all the targets belonging to the pertaining compartment is returned.
    The list does not include any subcompartments of the compartment under consideration.

    The parameter 'accessLevel' specifies whether to return only those compartments for which the requestor has
    INSPECT permissions on at least one resource directly or indirectly (ACCESSIBLE) (the resource can be in a
    subcompartment) or to return Not Authorized if Principal doesn't have access to even one of the child compartments.
    This is valid only when 'compartmentIdInSubtree' is set to 'true'.

    The parameter 'compartmentIdInSubtree' applies when you perform ListUserProfiles on the 'compartmentId' belonging
    to the assessmentId passed and when it is set to true, the entire hierarchy of compartments can be returned.
    To get a full list of all compartments and subcompartments in the tenancy (root compartment), set the parameter
    'compartmentIdInSubtree' to true and 'accessLevel' to ACCESSIBLE.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_user_assessment_profiles = oci.DataSafe.get_user_assessment_profiles(compartment_id=var["compartment_id"],
        user_assessment_id=oci_data_safe_user_assessment["test_user_assessment"]["id"],
        access_level=var["user_assessment_profile_access_level"],
        compartment_id_in_subtree=var["user_assessment_profile_compartment_id_in_subtree"],
        failed_login_attempts_greater_than_or_equal=var["user_assessment_profile_failed_login_attempts_greater_than_or_equal"],
        failed_login_attempts_less_than=var["user_assessment_profile_failed_login_attempts_less_than"],
        inactive_account_time_greater_than_or_equal=var["user_assessment_profile_inactive_account_time_greater_than_or_equal"],
        inactive_account_time_less_than=var["user_assessment_profile_inactive_account_time_less_than"],
        is_user_created=var["user_assessment_profile_is_user_created"],
        password_lock_time_greater_than_or_equal=var["user_assessment_profile_password_lock_time_greater_than_or_equal"],
        password_lock_time_less_than=var["user_assessment_profile_password_lock_time_less_than"],
        password_verification_function=var["user_assessment_profile_password_verification_function"],
        profile_name=oci_optimizer_profile["test_profile"]["name"],
        sessions_per_user_greater_than_or_equal=var["user_assessment_profile_sessions_per_user_greater_than_or_equal"],
        sessions_per_user_less_than=var["user_assessment_profile_sessions_per_user_less_than"],
        target_id=oci_cloud_guard_target["test_target"]["id"],
        user_count_greater_than_or_equal=var["user_assessment_profile_user_count_greater_than_or_equal"],
        user_count_less_than=var["user_assessment_profile_user_count_less_than"])
    ```


    :param str access_level: Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
    :param str compartment_id: A filter to return only resources that match the specified compartment OCID.
    :param bool compartment_id_in_subtree: Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
    :param str failed_login_attempts_greater_than_or_equal: An optional filter to return the profiles having allow failed login attempts number greater than or equal to the provided value. String value is used for accommodating the "UNLIMITED" and "DEFAULT" values.
    :param str failed_login_attempts_less_than: An optional filter to return the profiles having failed login attempts number less than the provided value. String value is used for accommodating the "UNLIMITED" and "DEFAULT" values.
    :param str inactive_account_time_greater_than_or_equal: An optional filter to return the profiles allowing inactive account time in days greater than or equal to the provided value. String value is used for accommodating the "UNLIMITED" and "DEFAULT" values.
    :param str inactive_account_time_less_than: An optional filter to return the profiles  allowing inactive account time in days less than the provided value. String value is used for accommodating the "UNLIMITED" and "DEFAULT" values.
    :param bool is_user_created: An optional filter to return the user created profiles.
    :param str password_lock_time_greater_than_or_equal: An optional filter to return the profiles having password lock number greater than or equal to the provided value. String value is used for accommodating the "UNLIMITED" and "DEFAULT" values.
    :param str password_lock_time_less_than: An optional filter to return the profiles having password lock number less than the provided value. String value is used for accommodating the "UNLIMITED" and "DEFAULT" values.
    :param str password_verification_function: An optional filter to filter the profiles based on password verification function.
    :param str profile_name: A filter to return only items that match the specified profile name.
    :param str sessions_per_user_greater_than_or_equal: An optional filter to return the profiles permitting the user to spawn multiple sessions having count. greater than or equal to the provided value. String value is used for accommodating the "UNLIMITED" and "DEFAULT" values.
    :param str sessions_per_user_less_than: An optional filter to return the profiles permitting the user to spawn multiple sessions having count less than the provided value. String value is used for accommodating the "UNLIMITED" and "DEFAULT" values.
    :param str target_id: A filter to return only items related to a specific target OCID.
    :param str user_assessment_id: The OCID of the user assessment.
    :param str user_count_greater_than_or_equal: An optional filter to return the profiles having user count greater than or equal to the provided value.
    :param str user_count_less_than: An optional filter to return the profiles having user count less than the provided value.
    """
    ...