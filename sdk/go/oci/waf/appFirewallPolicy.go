// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package waf

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Web App Firewall Policy resource in Oracle Cloud Infrastructure Waf service.
//
// Creates a new WebAppFirewallPolicy.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/waf"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := waf.NewAppFirewallPolicy(ctx, "test_web_app_firewall_policy", &waf.AppFirewallPolicyArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				Actions: waf.AppFirewallPolicyActionArray{
//					&waf.AppFirewallPolicyActionArgs{
//						Name: pulumi.Any(webAppFirewallPolicyActionsName),
//						Type: pulumi.Any(webAppFirewallPolicyActionsType),
//						Body: &waf.AppFirewallPolicyActionBodyArgs{
//							Text: pulumi.Any(webAppFirewallPolicyActionsBodyText),
//							Type: pulumi.Any(webAppFirewallPolicyActionsBodyType),
//						},
//						Code: pulumi.Any(webAppFirewallPolicyActionsCode),
//						Headers: waf.AppFirewallPolicyActionHeaderArray{
//							&waf.AppFirewallPolicyActionHeaderArgs{
//								Name:  pulumi.Any(webAppFirewallPolicyActionsHeadersName),
//								Value: pulumi.Any(webAppFirewallPolicyActionsHeadersValue),
//							},
//						},
//					},
//				},
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				DisplayName: pulumi.Any(webAppFirewallPolicyDisplayName),
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//				RequestAccessControl: &waf.AppFirewallPolicyRequestAccessControlArgs{
//					DefaultActionName: pulumi.Any(webAppFirewallPolicyRequestAccessControlDefaultActionName),
//					Rules: waf.AppFirewallPolicyRequestAccessControlRuleArray{
//						&waf.AppFirewallPolicyRequestAccessControlRuleArgs{
//							ActionName:        pulumi.Any(webAppFirewallPolicyRequestAccessControlRulesActionName),
//							Name:              pulumi.Any(webAppFirewallPolicyRequestAccessControlRulesName),
//							Type:              pulumi.Any(webAppFirewallPolicyRequestAccessControlRulesType),
//							Condition:         pulumi.Any(webAppFirewallPolicyRequestAccessControlRulesCondition),
//							ConditionLanguage: pulumi.Any(webAppFirewallPolicyRequestAccessControlRulesConditionLanguage),
//						},
//					},
//				},
//				RequestProtection: &waf.AppFirewallPolicyRequestProtectionArgs{
//					BodyInspectionSizeLimitExceededActionName: pulumi.Any(webAppFirewallPolicyRequestProtectionBodyInspectionSizeLimitExceededActionName),
//					BodyInspectionSizeLimitInBytes:            pulumi.Any(webAppFirewallPolicyRequestProtectionBodyInspectionSizeLimitInBytes),
//					Rules: waf.AppFirewallPolicyRequestProtectionRuleArray{
//						&waf.AppFirewallPolicyRequestProtectionRuleArgs{
//							ActionName: pulumi.Any(webAppFirewallPolicyRequestProtectionRulesActionName),
//							Name:       pulumi.Any(webAppFirewallPolicyRequestProtectionRulesName),
//							ProtectionCapabilities: waf.AppFirewallPolicyRequestProtectionRuleProtectionCapabilityArray{
//								&waf.AppFirewallPolicyRequestProtectionRuleProtectionCapabilityArgs{
//									Key:                          pulumi.Any(webAppFirewallPolicyRequestProtectionRulesProtectionCapabilitiesKey),
//									Version:                      pulumi.Any(webAppFirewallPolicyRequestProtectionRulesProtectionCapabilitiesVersion),
//									ActionName:                   pulumi.Any(webAppFirewallPolicyRequestProtectionRulesProtectionCapabilitiesActionName),
//									CollaborativeActionThreshold: pulumi.Any(webAppFirewallPolicyRequestProtectionRulesProtectionCapabilitiesCollaborativeActionThreshold),
//									CollaborativeWeights: waf.AppFirewallPolicyRequestProtectionRuleProtectionCapabilityCollaborativeWeightArray{
//										&waf.AppFirewallPolicyRequestProtectionRuleProtectionCapabilityCollaborativeWeightArgs{
//											Key:    pulumi.Any(webAppFirewallPolicyRequestProtectionRulesProtectionCapabilitiesCollaborativeWeightsKey),
//											Weight: pulumi.Any(webAppFirewallPolicyRequestProtectionRulesProtectionCapabilitiesCollaborativeWeightsWeight),
//										},
//									},
//									Exclusions: &waf.AppFirewallPolicyRequestProtectionRuleProtectionCapabilityExclusionsArgs{
//										Args:           pulumi.Any(webAppFirewallPolicyRequestProtectionRulesProtectionCapabilitiesExclusionsArgs),
//										RequestCookies: pulumi.Any(webAppFirewallPolicyRequestProtectionRulesProtectionCapabilitiesExclusionsRequestCookies),
//									},
//								},
//							},
//							Type:                    pulumi.Any(webAppFirewallPolicyRequestProtectionRulesType),
//							Condition:               pulumi.Any(webAppFirewallPolicyRequestProtectionRulesCondition),
//							ConditionLanguage:       pulumi.Any(webAppFirewallPolicyRequestProtectionRulesConditionLanguage),
//							IsBodyInspectionEnabled: pulumi.Any(webAppFirewallPolicyRequestProtectionRulesIsBodyInspectionEnabled),
//							ProtectionCapabilitySettings: &waf.AppFirewallPolicyRequestProtectionRuleProtectionCapabilitySettingsArgs{
//								AllowedHttpMethods:         pulumi.Any(webAppFirewallPolicyRequestProtectionRulesProtectionCapabilitySettingsAllowedHttpMethods),
//								MaxHttpRequestHeaderLength: pulumi.Any(webAppFirewallPolicyRequestProtectionRulesProtectionCapabilitySettingsMaxHttpRequestHeaderLength),
//								MaxHttpRequestHeaders:      pulumi.Any(webAppFirewallPolicyRequestProtectionRulesProtectionCapabilitySettingsMaxHttpRequestHeaders),
//								MaxNumberOfArguments:       pulumi.Any(webAppFirewallPolicyRequestProtectionRulesProtectionCapabilitySettingsMaxNumberOfArguments),
//								MaxSingleArgumentLength:    pulumi.Any(webAppFirewallPolicyRequestProtectionRulesProtectionCapabilitySettingsMaxSingleArgumentLength),
//								MaxTotalArgumentLength:     pulumi.Any(webAppFirewallPolicyRequestProtectionRulesProtectionCapabilitySettingsMaxTotalArgumentLength),
//							},
//						},
//					},
//				},
//				RequestRateLimiting: &waf.AppFirewallPolicyRequestRateLimitingArgs{
//					Rules: waf.AppFirewallPolicyRequestRateLimitingRuleArray{
//						&waf.AppFirewallPolicyRequestRateLimitingRuleArgs{
//							ActionName: pulumi.Any(webAppFirewallPolicyRequestRateLimitingRulesActionName),
//							Configurations: waf.AppFirewallPolicyRequestRateLimitingRuleConfigurationArray{
//								&waf.AppFirewallPolicyRequestRateLimitingRuleConfigurationArgs{
//									PeriodInSeconds:         pulumi.Any(webAppFirewallPolicyRequestRateLimitingRulesConfigurationsPeriodInSeconds),
//									RequestsLimit:           pulumi.Any(webAppFirewallPolicyRequestRateLimitingRulesConfigurationsRequestsLimit),
//									ActionDurationInSeconds: pulumi.Any(webAppFirewallPolicyRequestRateLimitingRulesConfigurationsActionDurationInSeconds),
//								},
//							},
//							Name:              pulumi.Any(webAppFirewallPolicyRequestRateLimitingRulesName),
//							Type:              pulumi.Any(webAppFirewallPolicyRequestRateLimitingRulesType),
//							Condition:         pulumi.Any(webAppFirewallPolicyRequestRateLimitingRulesCondition),
//							ConditionLanguage: pulumi.Any(webAppFirewallPolicyRequestRateLimitingRulesConditionLanguage),
//						},
//					},
//				},
//				ResponseAccessControl: &waf.AppFirewallPolicyResponseAccessControlArgs{
//					Rules: waf.AppFirewallPolicyResponseAccessControlRuleArray{
//						&waf.AppFirewallPolicyResponseAccessControlRuleArgs{
//							ActionName:        pulumi.Any(webAppFirewallPolicyResponseAccessControlRulesActionName),
//							Name:              pulumi.Any(webAppFirewallPolicyResponseAccessControlRulesName),
//							Type:              pulumi.Any(webAppFirewallPolicyResponseAccessControlRulesType),
//							Condition:         pulumi.Any(webAppFirewallPolicyResponseAccessControlRulesCondition),
//							ConditionLanguage: pulumi.Any(webAppFirewallPolicyResponseAccessControlRulesConditionLanguage),
//						},
//					},
//				},
//				ResponseProtection: &waf.AppFirewallPolicyResponseProtectionArgs{
//					Rules: waf.AppFirewallPolicyResponseProtectionRuleArray{
//						&waf.AppFirewallPolicyResponseProtectionRuleArgs{
//							ActionName: pulumi.Any(webAppFirewallPolicyResponseProtectionRulesActionName),
//							Name:       pulumi.Any(webAppFirewallPolicyResponseProtectionRulesName),
//							ProtectionCapabilities: waf.AppFirewallPolicyResponseProtectionRuleProtectionCapabilityArray{
//								&waf.AppFirewallPolicyResponseProtectionRuleProtectionCapabilityArgs{
//									Key:                          pulumi.Any(webAppFirewallPolicyResponseProtectionRulesProtectionCapabilitiesKey),
//									Version:                      pulumi.Any(webAppFirewallPolicyResponseProtectionRulesProtectionCapabilitiesVersion),
//									ActionName:                   pulumi.Any(webAppFirewallPolicyResponseProtectionRulesProtectionCapabilitiesActionName),
//									CollaborativeActionThreshold: pulumi.Any(webAppFirewallPolicyResponseProtectionRulesProtectionCapabilitiesCollaborativeActionThreshold),
//									CollaborativeWeights: waf.AppFirewallPolicyResponseProtectionRuleProtectionCapabilityCollaborativeWeightArray{
//										&waf.AppFirewallPolicyResponseProtectionRuleProtectionCapabilityCollaborativeWeightArgs{
//											Key:    pulumi.Any(webAppFirewallPolicyResponseProtectionRulesProtectionCapabilitiesCollaborativeWeightsKey),
//											Weight: pulumi.Any(webAppFirewallPolicyResponseProtectionRulesProtectionCapabilitiesCollaborativeWeightsWeight),
//										},
//									},
//									Exclusions: &waf.AppFirewallPolicyResponseProtectionRuleProtectionCapabilityExclusionsArgs{
//										Args:           pulumi.Any(webAppFirewallPolicyResponseProtectionRulesProtectionCapabilitiesExclusionsArgs),
//										RequestCookies: pulumi.Any(webAppFirewallPolicyResponseProtectionRulesProtectionCapabilitiesExclusionsRequestCookies),
//									},
//								},
//							},
//							Type:                    pulumi.Any(webAppFirewallPolicyResponseProtectionRulesType),
//							Condition:               pulumi.Any(webAppFirewallPolicyResponseProtectionRulesCondition),
//							ConditionLanguage:       pulumi.Any(webAppFirewallPolicyResponseProtectionRulesConditionLanguage),
//							IsBodyInspectionEnabled: pulumi.Any(webAppFirewallPolicyResponseProtectionRulesIsBodyInspectionEnabled),
//							ProtectionCapabilitySettings: &waf.AppFirewallPolicyResponseProtectionRuleProtectionCapabilitySettingsArgs{
//								AllowedHttpMethods:         pulumi.Any(webAppFirewallPolicyResponseProtectionRulesProtectionCapabilitySettingsAllowedHttpMethods),
//								MaxHttpRequestHeaderLength: pulumi.Any(webAppFirewallPolicyResponseProtectionRulesProtectionCapabilitySettingsMaxHttpRequestHeaderLength),
//								MaxHttpRequestHeaders:      pulumi.Any(webAppFirewallPolicyResponseProtectionRulesProtectionCapabilitySettingsMaxHttpRequestHeaders),
//								MaxNumberOfArguments:       pulumi.Any(webAppFirewallPolicyResponseProtectionRulesProtectionCapabilitySettingsMaxNumberOfArguments),
//								MaxSingleArgumentLength:    pulumi.Any(webAppFirewallPolicyResponseProtectionRulesProtectionCapabilitySettingsMaxSingleArgumentLength),
//								MaxTotalArgumentLength:     pulumi.Any(webAppFirewallPolicyResponseProtectionRulesProtectionCapabilitySettingsMaxTotalArgumentLength),
//							},
//						},
//					},
//				},
//				SystemTags: pulumi.Any(webAppFirewallPolicySystemTags),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// WebAppFirewallPolicies can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Waf/appFirewallPolicy:AppFirewallPolicy test_web_app_firewall_policy "id"
// ```
type AppFirewallPolicy struct {
	pulumi.CustomResourceState

	// (Updatable) Predefined actions for use in multiple different rules. Not all actions are supported in every module. Some actions terminate further execution of modules and rules in a module and some do not. Actions names must be unique within this array.
	Actions AppFirewallPolicyActionArrayOutput `pulumi:"actions"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) WebAppFirewallPolicy display name, can be renamed.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// (Updatable) Module that allows inspection of HTTP request properties and to return a defined HTTP response. In this module, rules with the name 'Default Action' are not allowed, since this name is reserved for default action logs.
	RequestAccessControl AppFirewallPolicyRequestAccessControlOutput `pulumi:"requestAccessControl"`
	// (Updatable) Module that allows to enable OCI-managed protection capabilities for incoming HTTP requests.
	RequestProtection AppFirewallPolicyRequestProtectionOutput `pulumi:"requestProtection"`
	// (Updatable) Module that allows inspection of HTTP connection properties and to limit requests frequency for a given key.
	RequestRateLimiting AppFirewallPolicyRequestRateLimitingOutput `pulumi:"requestRateLimiting"`
	// (Updatable) Module that allows inspection of HTTP response properties and to return a defined HTTP response.
	ResponseAccessControl AppFirewallPolicyResponseAccessControlOutput `pulumi:"responseAccessControl"`
	// (Updatable) Module that allows to enable OCI-managed protection capabilities for HTTP responses.
	ResponseProtection AppFirewallPolicyResponseProtectionOutput `pulumi:"responseProtection"`
	// The current state of the WebAppFirewallPolicy.
	State pulumi.StringOutput `pulumi:"state"`
	// (Updatable) Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The time the WebAppFirewallPolicy was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the WebAppFirewallPolicy was updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewAppFirewallPolicy registers a new resource with the given unique name, arguments, and options.
func NewAppFirewallPolicy(ctx *pulumi.Context,
	name string, args *AppFirewallPolicyArgs, opts ...pulumi.ResourceOption) (*AppFirewallPolicy, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource AppFirewallPolicy
	err := ctx.RegisterResource("oci:Waf/appFirewallPolicy:AppFirewallPolicy", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetAppFirewallPolicy gets an existing AppFirewallPolicy resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetAppFirewallPolicy(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *AppFirewallPolicyState, opts ...pulumi.ResourceOption) (*AppFirewallPolicy, error) {
	var resource AppFirewallPolicy
	err := ctx.ReadResource("oci:Waf/appFirewallPolicy:AppFirewallPolicy", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering AppFirewallPolicy resources.
type appFirewallPolicyState struct {
	// (Updatable) Predefined actions for use in multiple different rules. Not all actions are supported in every module. Some actions terminate further execution of modules and rules in a module and some do not. Actions names must be unique within this array.
	Actions []AppFirewallPolicyAction `pulumi:"actions"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) WebAppFirewallPolicy display name, can be renamed.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// (Updatable) Module that allows inspection of HTTP request properties and to return a defined HTTP response. In this module, rules with the name 'Default Action' are not allowed, since this name is reserved for default action logs.
	RequestAccessControl *AppFirewallPolicyRequestAccessControl `pulumi:"requestAccessControl"`
	// (Updatable) Module that allows to enable OCI-managed protection capabilities for incoming HTTP requests.
	RequestProtection *AppFirewallPolicyRequestProtection `pulumi:"requestProtection"`
	// (Updatable) Module that allows inspection of HTTP connection properties and to limit requests frequency for a given key.
	RequestRateLimiting *AppFirewallPolicyRequestRateLimiting `pulumi:"requestRateLimiting"`
	// (Updatable) Module that allows inspection of HTTP response properties and to return a defined HTTP response.
	ResponseAccessControl *AppFirewallPolicyResponseAccessControl `pulumi:"responseAccessControl"`
	// (Updatable) Module that allows to enable OCI-managed protection capabilities for HTTP responses.
	ResponseProtection *AppFirewallPolicyResponseProtection `pulumi:"responseProtection"`
	// The current state of the WebAppFirewallPolicy.
	State *string `pulumi:"state"`
	// (Updatable) Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time the WebAppFirewallPolicy was created. An RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the WebAppFirewallPolicy was updated. An RFC3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type AppFirewallPolicyState struct {
	// (Updatable) Predefined actions for use in multiple different rules. Not all actions are supported in every module. Some actions terminate further execution of modules and rules in a module and some do not. Actions names must be unique within this array.
	Actions AppFirewallPolicyActionArrayInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) WebAppFirewallPolicy display name, can be renamed.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
	LifecycleDetails pulumi.StringPtrInput
	// (Updatable) Module that allows inspection of HTTP request properties and to return a defined HTTP response. In this module, rules with the name 'Default Action' are not allowed, since this name is reserved for default action logs.
	RequestAccessControl AppFirewallPolicyRequestAccessControlPtrInput
	// (Updatable) Module that allows to enable OCI-managed protection capabilities for incoming HTTP requests.
	RequestProtection AppFirewallPolicyRequestProtectionPtrInput
	// (Updatable) Module that allows inspection of HTTP connection properties and to limit requests frequency for a given key.
	RequestRateLimiting AppFirewallPolicyRequestRateLimitingPtrInput
	// (Updatable) Module that allows inspection of HTTP response properties and to return a defined HTTP response.
	ResponseAccessControl AppFirewallPolicyResponseAccessControlPtrInput
	// (Updatable) Module that allows to enable OCI-managed protection capabilities for HTTP responses.
	ResponseProtection AppFirewallPolicyResponseProtectionPtrInput
	// The current state of the WebAppFirewallPolicy.
	State pulumi.StringPtrInput
	// (Updatable) Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SystemTags pulumi.StringMapInput
	// The time the WebAppFirewallPolicy was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time the WebAppFirewallPolicy was updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
}

func (AppFirewallPolicyState) ElementType() reflect.Type {
	return reflect.TypeOf((*appFirewallPolicyState)(nil)).Elem()
}

type appFirewallPolicyArgs struct {
	// (Updatable) Predefined actions for use in multiple different rules. Not all actions are supported in every module. Some actions terminate further execution of modules and rules in a module and some do not. Actions names must be unique within this array.
	Actions []AppFirewallPolicyAction `pulumi:"actions"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) WebAppFirewallPolicy display name, can be renamed.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) Module that allows inspection of HTTP request properties and to return a defined HTTP response. In this module, rules with the name 'Default Action' are not allowed, since this name is reserved for default action logs.
	RequestAccessControl *AppFirewallPolicyRequestAccessControl `pulumi:"requestAccessControl"`
	// (Updatable) Module that allows to enable OCI-managed protection capabilities for incoming HTTP requests.
	RequestProtection *AppFirewallPolicyRequestProtection `pulumi:"requestProtection"`
	// (Updatable) Module that allows inspection of HTTP connection properties and to limit requests frequency for a given key.
	RequestRateLimiting *AppFirewallPolicyRequestRateLimiting `pulumi:"requestRateLimiting"`
	// (Updatable) Module that allows inspection of HTTP response properties and to return a defined HTTP response.
	ResponseAccessControl *AppFirewallPolicyResponseAccessControl `pulumi:"responseAccessControl"`
	// (Updatable) Module that allows to enable OCI-managed protection capabilities for HTTP responses.
	ResponseProtection *AppFirewallPolicyResponseProtection `pulumi:"responseProtection"`
	// (Updatable) Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SystemTags map[string]string `pulumi:"systemTags"`
}

// The set of arguments for constructing a AppFirewallPolicy resource.
type AppFirewallPolicyArgs struct {
	// (Updatable) Predefined actions for use in multiple different rules. Not all actions are supported in every module. Some actions terminate further execution of modules and rules in a module and some do not. Actions names must be unique within this array.
	Actions AppFirewallPolicyActionArrayInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) WebAppFirewallPolicy display name, can be renamed.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) Module that allows inspection of HTTP request properties and to return a defined HTTP response. In this module, rules with the name 'Default Action' are not allowed, since this name is reserved for default action logs.
	RequestAccessControl AppFirewallPolicyRequestAccessControlPtrInput
	// (Updatable) Module that allows to enable OCI-managed protection capabilities for incoming HTTP requests.
	RequestProtection AppFirewallPolicyRequestProtectionPtrInput
	// (Updatable) Module that allows inspection of HTTP connection properties and to limit requests frequency for a given key.
	RequestRateLimiting AppFirewallPolicyRequestRateLimitingPtrInput
	// (Updatable) Module that allows inspection of HTTP response properties and to return a defined HTTP response.
	ResponseAccessControl AppFirewallPolicyResponseAccessControlPtrInput
	// (Updatable) Module that allows to enable OCI-managed protection capabilities for HTTP responses.
	ResponseProtection AppFirewallPolicyResponseProtectionPtrInput
	// (Updatable) Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SystemTags pulumi.StringMapInput
}

func (AppFirewallPolicyArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*appFirewallPolicyArgs)(nil)).Elem()
}

type AppFirewallPolicyInput interface {
	pulumi.Input

	ToAppFirewallPolicyOutput() AppFirewallPolicyOutput
	ToAppFirewallPolicyOutputWithContext(ctx context.Context) AppFirewallPolicyOutput
}

func (*AppFirewallPolicy) ElementType() reflect.Type {
	return reflect.TypeOf((**AppFirewallPolicy)(nil)).Elem()
}

func (i *AppFirewallPolicy) ToAppFirewallPolicyOutput() AppFirewallPolicyOutput {
	return i.ToAppFirewallPolicyOutputWithContext(context.Background())
}

func (i *AppFirewallPolicy) ToAppFirewallPolicyOutputWithContext(ctx context.Context) AppFirewallPolicyOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AppFirewallPolicyOutput)
}

// AppFirewallPolicyArrayInput is an input type that accepts AppFirewallPolicyArray and AppFirewallPolicyArrayOutput values.
// You can construct a concrete instance of `AppFirewallPolicyArrayInput` via:
//
//	AppFirewallPolicyArray{ AppFirewallPolicyArgs{...} }
type AppFirewallPolicyArrayInput interface {
	pulumi.Input

	ToAppFirewallPolicyArrayOutput() AppFirewallPolicyArrayOutput
	ToAppFirewallPolicyArrayOutputWithContext(context.Context) AppFirewallPolicyArrayOutput
}

type AppFirewallPolicyArray []AppFirewallPolicyInput

func (AppFirewallPolicyArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AppFirewallPolicy)(nil)).Elem()
}

func (i AppFirewallPolicyArray) ToAppFirewallPolicyArrayOutput() AppFirewallPolicyArrayOutput {
	return i.ToAppFirewallPolicyArrayOutputWithContext(context.Background())
}

func (i AppFirewallPolicyArray) ToAppFirewallPolicyArrayOutputWithContext(ctx context.Context) AppFirewallPolicyArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AppFirewallPolicyArrayOutput)
}

// AppFirewallPolicyMapInput is an input type that accepts AppFirewallPolicyMap and AppFirewallPolicyMapOutput values.
// You can construct a concrete instance of `AppFirewallPolicyMapInput` via:
//
//	AppFirewallPolicyMap{ "key": AppFirewallPolicyArgs{...} }
type AppFirewallPolicyMapInput interface {
	pulumi.Input

	ToAppFirewallPolicyMapOutput() AppFirewallPolicyMapOutput
	ToAppFirewallPolicyMapOutputWithContext(context.Context) AppFirewallPolicyMapOutput
}

type AppFirewallPolicyMap map[string]AppFirewallPolicyInput

func (AppFirewallPolicyMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AppFirewallPolicy)(nil)).Elem()
}

func (i AppFirewallPolicyMap) ToAppFirewallPolicyMapOutput() AppFirewallPolicyMapOutput {
	return i.ToAppFirewallPolicyMapOutputWithContext(context.Background())
}

func (i AppFirewallPolicyMap) ToAppFirewallPolicyMapOutputWithContext(ctx context.Context) AppFirewallPolicyMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AppFirewallPolicyMapOutput)
}

type AppFirewallPolicyOutput struct{ *pulumi.OutputState }

func (AppFirewallPolicyOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**AppFirewallPolicy)(nil)).Elem()
}

func (o AppFirewallPolicyOutput) ToAppFirewallPolicyOutput() AppFirewallPolicyOutput {
	return o
}

func (o AppFirewallPolicyOutput) ToAppFirewallPolicyOutputWithContext(ctx context.Context) AppFirewallPolicyOutput {
	return o
}

// (Updatable) Predefined actions for use in multiple different rules. Not all actions are supported in every module. Some actions terminate further execution of modules and rules in a module and some do not. Actions names must be unique within this array.
func (o AppFirewallPolicyOutput) Actions() AppFirewallPolicyActionArrayOutput {
	return o.ApplyT(func(v *AppFirewallPolicy) AppFirewallPolicyActionArrayOutput { return v.Actions }).(AppFirewallPolicyActionArrayOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o AppFirewallPolicyOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *AppFirewallPolicy) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o AppFirewallPolicyOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *AppFirewallPolicy) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) WebAppFirewallPolicy display name, can be renamed.
func (o AppFirewallPolicyOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *AppFirewallPolicy) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o AppFirewallPolicyOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *AppFirewallPolicy) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
func (o AppFirewallPolicyOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *AppFirewallPolicy) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// (Updatable) Module that allows inspection of HTTP request properties and to return a defined HTTP response. In this module, rules with the name 'Default Action' are not allowed, since this name is reserved for default action logs.
func (o AppFirewallPolicyOutput) RequestAccessControl() AppFirewallPolicyRequestAccessControlOutput {
	return o.ApplyT(func(v *AppFirewallPolicy) AppFirewallPolicyRequestAccessControlOutput { return v.RequestAccessControl }).(AppFirewallPolicyRequestAccessControlOutput)
}

// (Updatable) Module that allows to enable OCI-managed protection capabilities for incoming HTTP requests.
func (o AppFirewallPolicyOutput) RequestProtection() AppFirewallPolicyRequestProtectionOutput {
	return o.ApplyT(func(v *AppFirewallPolicy) AppFirewallPolicyRequestProtectionOutput { return v.RequestProtection }).(AppFirewallPolicyRequestProtectionOutput)
}

// (Updatable) Module that allows inspection of HTTP connection properties and to limit requests frequency for a given key.
func (o AppFirewallPolicyOutput) RequestRateLimiting() AppFirewallPolicyRequestRateLimitingOutput {
	return o.ApplyT(func(v *AppFirewallPolicy) AppFirewallPolicyRequestRateLimitingOutput { return v.RequestRateLimiting }).(AppFirewallPolicyRequestRateLimitingOutput)
}

// (Updatable) Module that allows inspection of HTTP response properties and to return a defined HTTP response.
func (o AppFirewallPolicyOutput) ResponseAccessControl() AppFirewallPolicyResponseAccessControlOutput {
	return o.ApplyT(func(v *AppFirewallPolicy) AppFirewallPolicyResponseAccessControlOutput {
		return v.ResponseAccessControl
	}).(AppFirewallPolicyResponseAccessControlOutput)
}

// (Updatable) Module that allows to enable OCI-managed protection capabilities for HTTP responses.
func (o AppFirewallPolicyOutput) ResponseProtection() AppFirewallPolicyResponseProtectionOutput {
	return o.ApplyT(func(v *AppFirewallPolicy) AppFirewallPolicyResponseProtectionOutput { return v.ResponseProtection }).(AppFirewallPolicyResponseProtectionOutput)
}

// The current state of the WebAppFirewallPolicy.
func (o AppFirewallPolicyOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *AppFirewallPolicy) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// (Updatable) Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o AppFirewallPolicyOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *AppFirewallPolicy) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time the WebAppFirewallPolicy was created. An RFC3339 formatted datetime string.
func (o AppFirewallPolicyOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *AppFirewallPolicy) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the WebAppFirewallPolicy was updated. An RFC3339 formatted datetime string.
func (o AppFirewallPolicyOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *AppFirewallPolicy) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type AppFirewallPolicyArrayOutput struct{ *pulumi.OutputState }

func (AppFirewallPolicyArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AppFirewallPolicy)(nil)).Elem()
}

func (o AppFirewallPolicyArrayOutput) ToAppFirewallPolicyArrayOutput() AppFirewallPolicyArrayOutput {
	return o
}

func (o AppFirewallPolicyArrayOutput) ToAppFirewallPolicyArrayOutputWithContext(ctx context.Context) AppFirewallPolicyArrayOutput {
	return o
}

func (o AppFirewallPolicyArrayOutput) Index(i pulumi.IntInput) AppFirewallPolicyOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *AppFirewallPolicy {
		return vs[0].([]*AppFirewallPolicy)[vs[1].(int)]
	}).(AppFirewallPolicyOutput)
}

type AppFirewallPolicyMapOutput struct{ *pulumi.OutputState }

func (AppFirewallPolicyMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AppFirewallPolicy)(nil)).Elem()
}

func (o AppFirewallPolicyMapOutput) ToAppFirewallPolicyMapOutput() AppFirewallPolicyMapOutput {
	return o
}

func (o AppFirewallPolicyMapOutput) ToAppFirewallPolicyMapOutputWithContext(ctx context.Context) AppFirewallPolicyMapOutput {
	return o
}

func (o AppFirewallPolicyMapOutput) MapIndex(k pulumi.StringInput) AppFirewallPolicyOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *AppFirewallPolicy {
		return vs[0].(map[string]*AppFirewallPolicy)[vs[1].(string)]
	}).(AppFirewallPolicyOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*AppFirewallPolicyInput)(nil)).Elem(), &AppFirewallPolicy{})
	pulumi.RegisterInputType(reflect.TypeOf((*AppFirewallPolicyArrayInput)(nil)).Elem(), AppFirewallPolicyArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*AppFirewallPolicyMapInput)(nil)).Elem(), AppFirewallPolicyMap{})
	pulumi.RegisterOutputType(AppFirewallPolicyOutput{})
	pulumi.RegisterOutputType(AppFirewallPolicyArrayOutput{})
	pulumi.RegisterOutputType(AppFirewallPolicyMapOutput{})
}
