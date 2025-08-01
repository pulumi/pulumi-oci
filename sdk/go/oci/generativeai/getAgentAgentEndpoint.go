// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package generativeai

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Agent Endpoint resource in Oracle Cloud Infrastructure Generative Ai Agent service.
//
// Gets information about an endpoint.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/generativeai"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := generativeai.GetAgentAgentEndpoint(ctx, &generativeai.GetAgentAgentEndpointArgs{
//				AgentEndpointId: testAgentEndpointOciGenerativeAiAgentAgentEndpoint.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupAgentAgentEndpoint(ctx *pulumi.Context, args *LookupAgentAgentEndpointArgs, opts ...pulumi.InvokeOption) (*LookupAgentAgentEndpointResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupAgentAgentEndpointResult
	err := ctx.Invoke("oci:GenerativeAi/getAgentAgentEndpoint:getAgentAgentEndpoint", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAgentAgentEndpoint.
type LookupAgentAgentEndpointArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the endpoint.
	AgentEndpointId string `pulumi:"agentEndpointId"`
}

// A collection of values returned by getAgentAgentEndpoint.
type LookupAgentAgentEndpointResult struct {
	AgentEndpointId string `pulumi:"agentEndpointId"`
	// The OCID of the agent that this endpoint is associated with.
	AgentId string `pulumi:"agentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The configuration details about whether to apply the content moderation feature to input and output. Content moderation removes toxic and biased content from responses. It is recommended to use content moderation.
	ContentModerationConfigs []GetAgentAgentEndpointContentModerationConfig `pulumi:"contentModerationConfigs"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// An optional description of the endpoint.
	Description string `pulumi:"description"`
	// A user-friendly name. Does not have to be unique, and it's changeable.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The configuration details about whether to apply the guardrail checks to input and output.
	GuardrailConfigs []GetAgentAgentEndpointGuardrailConfig `pulumi:"guardrailConfigs"`
	// Human Input Configuration for an AgentEndpoint.
	HumanInputConfigs []GetAgentAgentEndpointHumanInputConfig `pulumi:"humanInputConfigs"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the endpoint.
	Id string `pulumi:"id"`
	// A message that describes the current state of the endpoint in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// Key-value pairs to allow additional configurations.
	Metadata map[string]string `pulumi:"metadata"`
	// Configuration to store results generated by agent.
	OutputConfigs []GetAgentAgentEndpointOutputConfig `pulumi:"outputConfigs"`
	// Session Configuration on AgentEndpoint.
	SessionConfigs []GetAgentAgentEndpointSessionConfig `pulumi:"sessionConfigs"`
	// Whether to show citations in the chat result.
	ShouldEnableCitation bool `pulumi:"shouldEnableCitation"`
	// Whether to enable multi-language for chat.
	ShouldEnableMultiLanguage bool `pulumi:"shouldEnableMultiLanguage"`
	// Whether or not to enable Session-based chat.
	ShouldEnableSession bool `pulumi:"shouldEnableSession"`
	// Whether to show traces in the chat result.
	ShouldEnableTrace bool `pulumi:"shouldEnableTrace"`
	// The current state of the endpoint.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the AgentEndpoint was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the endpoint was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupAgentAgentEndpointOutput(ctx *pulumi.Context, args LookupAgentAgentEndpointOutputArgs, opts ...pulumi.InvokeOption) LookupAgentAgentEndpointResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupAgentAgentEndpointResultOutput, error) {
			args := v.(LookupAgentAgentEndpointArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:GenerativeAi/getAgentAgentEndpoint:getAgentAgentEndpoint", args, LookupAgentAgentEndpointResultOutput{}, options).(LookupAgentAgentEndpointResultOutput), nil
		}).(LookupAgentAgentEndpointResultOutput)
}

// A collection of arguments for invoking getAgentAgentEndpoint.
type LookupAgentAgentEndpointOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the endpoint.
	AgentEndpointId pulumi.StringInput `pulumi:"agentEndpointId"`
}

func (LookupAgentAgentEndpointOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupAgentAgentEndpointArgs)(nil)).Elem()
}

// A collection of values returned by getAgentAgentEndpoint.
type LookupAgentAgentEndpointResultOutput struct{ *pulumi.OutputState }

func (LookupAgentAgentEndpointResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupAgentAgentEndpointResult)(nil)).Elem()
}

func (o LookupAgentAgentEndpointResultOutput) ToLookupAgentAgentEndpointResultOutput() LookupAgentAgentEndpointResultOutput {
	return o
}

func (o LookupAgentAgentEndpointResultOutput) ToLookupAgentAgentEndpointResultOutputWithContext(ctx context.Context) LookupAgentAgentEndpointResultOutput {
	return o
}

func (o LookupAgentAgentEndpointResultOutput) AgentEndpointId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) string { return v.AgentEndpointId }).(pulumi.StringOutput)
}

// The OCID of the agent that this endpoint is associated with.
func (o LookupAgentAgentEndpointResultOutput) AgentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) string { return v.AgentId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o LookupAgentAgentEndpointResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The configuration details about whether to apply the content moderation feature to input and output. Content moderation removes toxic and biased content from responses. It is recommended to use content moderation.
func (o LookupAgentAgentEndpointResultOutput) ContentModerationConfigs() GetAgentAgentEndpointContentModerationConfigArrayOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) []GetAgentAgentEndpointContentModerationConfig {
		return v.ContentModerationConfigs
	}).(GetAgentAgentEndpointContentModerationConfigArrayOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o LookupAgentAgentEndpointResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// An optional description of the endpoint.
func (o LookupAgentAgentEndpointResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) string { return v.Description }).(pulumi.StringOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable.
func (o LookupAgentAgentEndpointResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupAgentAgentEndpointResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The configuration details about whether to apply the guardrail checks to input and output.
func (o LookupAgentAgentEndpointResultOutput) GuardrailConfigs() GetAgentAgentEndpointGuardrailConfigArrayOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) []GetAgentAgentEndpointGuardrailConfig {
		return v.GuardrailConfigs
	}).(GetAgentAgentEndpointGuardrailConfigArrayOutput)
}

// Human Input Configuration for an AgentEndpoint.
func (o LookupAgentAgentEndpointResultOutput) HumanInputConfigs() GetAgentAgentEndpointHumanInputConfigArrayOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) []GetAgentAgentEndpointHumanInputConfig {
		return v.HumanInputConfigs
	}).(GetAgentAgentEndpointHumanInputConfigArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the endpoint.
func (o LookupAgentAgentEndpointResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) string { return v.Id }).(pulumi.StringOutput)
}

// A message that describes the current state of the endpoint in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
func (o LookupAgentAgentEndpointResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Key-value pairs to allow additional configurations.
func (o LookupAgentAgentEndpointResultOutput) Metadata() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) map[string]string { return v.Metadata }).(pulumi.StringMapOutput)
}

// Configuration to store results generated by agent.
func (o LookupAgentAgentEndpointResultOutput) OutputConfigs() GetAgentAgentEndpointOutputConfigArrayOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) []GetAgentAgentEndpointOutputConfig { return v.OutputConfigs }).(GetAgentAgentEndpointOutputConfigArrayOutput)
}

// Session Configuration on AgentEndpoint.
func (o LookupAgentAgentEndpointResultOutput) SessionConfigs() GetAgentAgentEndpointSessionConfigArrayOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) []GetAgentAgentEndpointSessionConfig { return v.SessionConfigs }).(GetAgentAgentEndpointSessionConfigArrayOutput)
}

// Whether to show citations in the chat result.
func (o LookupAgentAgentEndpointResultOutput) ShouldEnableCitation() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) bool { return v.ShouldEnableCitation }).(pulumi.BoolOutput)
}

// Whether to enable multi-language for chat.
func (o LookupAgentAgentEndpointResultOutput) ShouldEnableMultiLanguage() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) bool { return v.ShouldEnableMultiLanguage }).(pulumi.BoolOutput)
}

// Whether or not to enable Session-based chat.
func (o LookupAgentAgentEndpointResultOutput) ShouldEnableSession() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) bool { return v.ShouldEnableSession }).(pulumi.BoolOutput)
}

// Whether to show traces in the chat result.
func (o LookupAgentAgentEndpointResultOutput) ShouldEnableTrace() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) bool { return v.ShouldEnableTrace }).(pulumi.BoolOutput)
}

// The current state of the endpoint.
func (o LookupAgentAgentEndpointResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupAgentAgentEndpointResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the AgentEndpoint was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o LookupAgentAgentEndpointResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the endpoint was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o LookupAgentAgentEndpointResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentEndpointResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupAgentAgentEndpointResultOutput{})
}
