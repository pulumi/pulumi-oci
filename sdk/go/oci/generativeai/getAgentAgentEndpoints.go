// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package generativeai

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Agent Endpoints in Oracle Cloud Infrastructure Generative Ai Agent service.
//
// Gets a list of endpoints.
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
//			_, err := generativeai.GetAgentAgentEndpoints(ctx, &generativeai.GetAgentAgentEndpointsArgs{
//				AgentId:       pulumi.StringRef(testAgent.Id),
//				CompartmentId: pulumi.StringRef(compartmentId),
//				DisplayName:   pulumi.StringRef(agentEndpointDisplayName),
//				State:         pulumi.StringRef(agentEndpointState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetAgentAgentEndpoints(ctx *pulumi.Context, args *GetAgentAgentEndpointsArgs, opts ...pulumi.InvokeOption) (*GetAgentAgentEndpointsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetAgentAgentEndpointsResult
	err := ctx.Invoke("oci:GenerativeAi/getAgentAgentEndpoints:getAgentAgentEndpoints", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAgentAgentEndpoints.
type GetAgentAgentEndpointsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent.
	AgentId *string `pulumi:"agentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string                        `pulumi:"displayName"`
	Filters     []GetAgentAgentEndpointsFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getAgentAgentEndpoints.
type GetAgentAgentEndpointsResult struct {
	// The list of agent_endpoint_collection.
	AgentEndpointCollections []GetAgentAgentEndpointsAgentEndpointCollection `pulumi:"agentEndpointCollections"`
	// The OCID of the agent that this endpoint is associated with.
	AgentId *string `pulumi:"agentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable.
	DisplayName *string                        `pulumi:"displayName"`
	Filters     []GetAgentAgentEndpointsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the endpoint.
	State *string `pulumi:"state"`
}

func GetAgentAgentEndpointsOutput(ctx *pulumi.Context, args GetAgentAgentEndpointsOutputArgs, opts ...pulumi.InvokeOption) GetAgentAgentEndpointsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetAgentAgentEndpointsResultOutput, error) {
			args := v.(GetAgentAgentEndpointsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:GenerativeAi/getAgentAgentEndpoints:getAgentAgentEndpoints", args, GetAgentAgentEndpointsResultOutput{}, options).(GetAgentAgentEndpointsResultOutput), nil
		}).(GetAgentAgentEndpointsResultOutput)
}

// A collection of arguments for invoking getAgentAgentEndpoints.
type GetAgentAgentEndpointsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent.
	AgentId pulumi.StringPtrInput `pulumi:"agentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName pulumi.StringPtrInput                  `pulumi:"displayName"`
	Filters     GetAgentAgentEndpointsFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetAgentAgentEndpointsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAgentAgentEndpointsArgs)(nil)).Elem()
}

// A collection of values returned by getAgentAgentEndpoints.
type GetAgentAgentEndpointsResultOutput struct{ *pulumi.OutputState }

func (GetAgentAgentEndpointsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAgentAgentEndpointsResult)(nil)).Elem()
}

func (o GetAgentAgentEndpointsResultOutput) ToGetAgentAgentEndpointsResultOutput() GetAgentAgentEndpointsResultOutput {
	return o
}

func (o GetAgentAgentEndpointsResultOutput) ToGetAgentAgentEndpointsResultOutputWithContext(ctx context.Context) GetAgentAgentEndpointsResultOutput {
	return o
}

// The list of agent_endpoint_collection.
func (o GetAgentAgentEndpointsResultOutput) AgentEndpointCollections() GetAgentAgentEndpointsAgentEndpointCollectionArrayOutput {
	return o.ApplyT(func(v GetAgentAgentEndpointsResult) []GetAgentAgentEndpointsAgentEndpointCollection {
		return v.AgentEndpointCollections
	}).(GetAgentAgentEndpointsAgentEndpointCollectionArrayOutput)
}

// The OCID of the agent that this endpoint is associated with.
func (o GetAgentAgentEndpointsResultOutput) AgentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAgentAgentEndpointsResult) *string { return v.AgentId }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o GetAgentAgentEndpointsResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAgentAgentEndpointsResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable.
func (o GetAgentAgentEndpointsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAgentAgentEndpointsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetAgentAgentEndpointsResultOutput) Filters() GetAgentAgentEndpointsFilterArrayOutput {
	return o.ApplyT(func(v GetAgentAgentEndpointsResult) []GetAgentAgentEndpointsFilter { return v.Filters }).(GetAgentAgentEndpointsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetAgentAgentEndpointsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetAgentAgentEndpointsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of the endpoint.
func (o GetAgentAgentEndpointsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAgentAgentEndpointsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetAgentAgentEndpointsResultOutput{})
}
