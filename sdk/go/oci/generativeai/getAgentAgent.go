// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package generativeai

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Agent resource in Oracle Cloud Infrastructure Generative Ai Agent service.
//
// **GetAgent**
//
// Gets information about an agent.
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
//			_, err := generativeai.GetAgentAgent(ctx, &generativeai.GetAgentAgentArgs{
//				AgentId: testAgentOciGenerativeAiAgentAgent.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupAgentAgent(ctx *pulumi.Context, args *LookupAgentAgentArgs, opts ...pulumi.InvokeOption) (*LookupAgentAgentResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupAgentAgentResult
	err := ctx.Invoke("oci:GenerativeAi/getAgentAgent:getAgentAgent", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAgentAgent.
type LookupAgentAgentArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent.
	AgentId string `pulumi:"agentId"`
}

// A collection of values returned by getAgentAgent.
type LookupAgentAgentResult struct {
	AgentId string `pulumi:"agentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Description about the agent.
	Description string `pulumi:"description"`
	// A user-friendly name. Does not have to be unique, and it's changeable.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent.
	Id string `pulumi:"id"`
	// List of [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the knowledgeBases associated with agent. This field is deprecated and will be removed after March 26 2026.
	KnowledgeBaseIds []string `pulumi:"knowledgeBaseIds"`
	// A message that describes the current state of the agent in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// Configuration to Agent LLM.
	LlmConfigs []GetAgentAgentLlmConfig `pulumi:"llmConfigs"`
	// The current state of the agent.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the agent was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the agent was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated string `pulumi:"timeUpdated"`
	// Details about purpose and responsibility of the agent
	WelcomeMessage string `pulumi:"welcomeMessage"`
}

func LookupAgentAgentOutput(ctx *pulumi.Context, args LookupAgentAgentOutputArgs, opts ...pulumi.InvokeOption) LookupAgentAgentResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupAgentAgentResultOutput, error) {
			args := v.(LookupAgentAgentArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:GenerativeAi/getAgentAgent:getAgentAgent", args, LookupAgentAgentResultOutput{}, options).(LookupAgentAgentResultOutput), nil
		}).(LookupAgentAgentResultOutput)
}

// A collection of arguments for invoking getAgentAgent.
type LookupAgentAgentOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent.
	AgentId pulumi.StringInput `pulumi:"agentId"`
}

func (LookupAgentAgentOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupAgentAgentArgs)(nil)).Elem()
}

// A collection of values returned by getAgentAgent.
type LookupAgentAgentResultOutput struct{ *pulumi.OutputState }

func (LookupAgentAgentResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupAgentAgentResult)(nil)).Elem()
}

func (o LookupAgentAgentResultOutput) ToLookupAgentAgentResultOutput() LookupAgentAgentResultOutput {
	return o
}

func (o LookupAgentAgentResultOutput) ToLookupAgentAgentResultOutputWithContext(ctx context.Context) LookupAgentAgentResultOutput {
	return o
}

func (o LookupAgentAgentResultOutput) AgentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentResult) string { return v.AgentId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o LookupAgentAgentResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o LookupAgentAgentResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupAgentAgentResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Description about the agent.
func (o LookupAgentAgentResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentResult) string { return v.Description }).(pulumi.StringOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable.
func (o LookupAgentAgentResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupAgentAgentResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupAgentAgentResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent.
func (o LookupAgentAgentResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentResult) string { return v.Id }).(pulumi.StringOutput)
}

// List of [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the knowledgeBases associated with agent. This field is deprecated and will be removed after March 26 2026.
func (o LookupAgentAgentResultOutput) KnowledgeBaseIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupAgentAgentResult) []string { return v.KnowledgeBaseIds }).(pulumi.StringArrayOutput)
}

// A message that describes the current state of the agent in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
func (o LookupAgentAgentResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Configuration to Agent LLM.
func (o LookupAgentAgentResultOutput) LlmConfigs() GetAgentAgentLlmConfigArrayOutput {
	return o.ApplyT(func(v LookupAgentAgentResult) []GetAgentAgentLlmConfig { return v.LlmConfigs }).(GetAgentAgentLlmConfigArrayOutput)
}

// The current state of the agent.
func (o LookupAgentAgentResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupAgentAgentResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupAgentAgentResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the agent was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o LookupAgentAgentResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the agent was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o LookupAgentAgentResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// Details about purpose and responsibility of the agent
func (o LookupAgentAgentResultOutput) WelcomeMessage() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAgentAgentResult) string { return v.WelcomeMessage }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupAgentAgentResultOutput{})
}
