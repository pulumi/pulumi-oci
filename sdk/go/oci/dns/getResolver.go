// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dns

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Resolver resource in Oracle Cloud Infrastructure DNS service.
//
// Gets information about a specific resolver.
//
// Note that attempting to get a resolver in the DELETED lifecycleState will result in a `404`
// response to be consistent with other operations of the API.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/dns"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := dns.GetResolver(ctx, &dns.GetResolverArgs{
//				ResolverId: testResolverOciDnsResolver.Id,
//				Scope:      pulumi.StringRef("PRIVATE"),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupResolver(ctx *pulumi.Context, args *LookupResolverArgs, opts ...pulumi.InvokeOption) (*LookupResolverResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupResolverResult
	err := ctx.Invoke("oci:Dns/getResolver:getResolver", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getResolver.
type LookupResolverArgs struct {
	// The OCID of the target resolver.
	ResolverId string `pulumi:"resolverId"`
	// Value must be `PRIVATE` when listing private name resolvers.
	Scope *string `pulumi:"scope"`
}

// A collection of values returned by getResolver.
type LookupResolverResult struct {
	// The OCID of the attached VCN.
	AttachedVcnId string `pulumi:"attachedVcnId"`
	// The attached views. Views are evaluated in order.
	AttachedViews []GetResolverAttachedView `pulumi:"attachedViews"`
	// The OCID of the owning compartment. This will match the resolver that the resolver endpoint is under and will be updated if the resolver's compartment is changed.
	CompartmentId string `pulumi:"compartmentId"`
	// The OCID of the default view.
	DefaultViewId string `pulumi:"defaultViewId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The display name of the resolver.
	DisplayName string `pulumi:"displayName"`
	// Read-only array of endpoints for the resolver.
	Endpoints []GetResolverEndpointType `pulumi:"endpoints"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the resolver.
	Id string `pulumi:"id"`
	// A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
	IsProtected bool   `pulumi:"isProtected"`
	ResolverId  string `pulumi:"resolverId"`
	// Rules for the resolver. Rules are evaluated in order.
	Rules []GetResolverRule `pulumi:"rules"`
	Scope *string           `pulumi:"scope"`
	// The canonical absolute URL of the resource.
	Self string `pulumi:"self"`
	// The current state of the resource.
	State string `pulumi:"state"`
	// The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the resource was last updated in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupResolverOutput(ctx *pulumi.Context, args LookupResolverOutputArgs, opts ...pulumi.InvokeOption) LookupResolverResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupResolverResultOutput, error) {
			args := v.(LookupResolverArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Dns/getResolver:getResolver", args, LookupResolverResultOutput{}, options).(LookupResolverResultOutput), nil
		}).(LookupResolverResultOutput)
}

// A collection of arguments for invoking getResolver.
type LookupResolverOutputArgs struct {
	// The OCID of the target resolver.
	ResolverId pulumi.StringInput `pulumi:"resolverId"`
	// Value must be `PRIVATE` when listing private name resolvers.
	Scope pulumi.StringPtrInput `pulumi:"scope"`
}

func (LookupResolverOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupResolverArgs)(nil)).Elem()
}

// A collection of values returned by getResolver.
type LookupResolverResultOutput struct{ *pulumi.OutputState }

func (LookupResolverResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupResolverResult)(nil)).Elem()
}

func (o LookupResolverResultOutput) ToLookupResolverResultOutput() LookupResolverResultOutput {
	return o
}

func (o LookupResolverResultOutput) ToLookupResolverResultOutputWithContext(ctx context.Context) LookupResolverResultOutput {
	return o
}

// The OCID of the attached VCN.
func (o LookupResolverResultOutput) AttachedVcnId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResolverResult) string { return v.AttachedVcnId }).(pulumi.StringOutput)
}

// The attached views. Views are evaluated in order.
func (o LookupResolverResultOutput) AttachedViews() GetResolverAttachedViewArrayOutput {
	return o.ApplyT(func(v LookupResolverResult) []GetResolverAttachedView { return v.AttachedViews }).(GetResolverAttachedViewArrayOutput)
}

// The OCID of the owning compartment. This will match the resolver that the resolver endpoint is under and will be updated if the resolver's compartment is changed.
func (o LookupResolverResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResolverResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The OCID of the default view.
func (o LookupResolverResultOutput) DefaultViewId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResolverResult) string { return v.DefaultViewId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o LookupResolverResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupResolverResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The display name of the resolver.
func (o LookupResolverResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResolverResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Read-only array of endpoints for the resolver.
func (o LookupResolverResultOutput) Endpoints() GetResolverEndpointTypeArrayOutput {
	return o.ApplyT(func(v LookupResolverResult) []GetResolverEndpointType { return v.Endpoints }).(GetResolverEndpointTypeArrayOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o LookupResolverResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupResolverResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The OCID of the resolver.
func (o LookupResolverResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResolverResult) string { return v.Id }).(pulumi.StringOutput)
}

// A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
func (o LookupResolverResultOutput) IsProtected() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupResolverResult) bool { return v.IsProtected }).(pulumi.BoolOutput)
}

func (o LookupResolverResultOutput) ResolverId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResolverResult) string { return v.ResolverId }).(pulumi.StringOutput)
}

// Rules for the resolver. Rules are evaluated in order.
func (o LookupResolverResultOutput) Rules() GetResolverRuleArrayOutput {
	return o.ApplyT(func(v LookupResolverResult) []GetResolverRule { return v.Rules }).(GetResolverRuleArrayOutput)
}

func (o LookupResolverResultOutput) Scope() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupResolverResult) *string { return v.Scope }).(pulumi.StringPtrOutput)
}

// The canonical absolute URL of the resource.
func (o LookupResolverResultOutput) Self() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResolverResult) string { return v.Self }).(pulumi.StringOutput)
}

// The current state of the resource.
func (o LookupResolverResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResolverResult) string { return v.State }).(pulumi.StringOutput)
}

// The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
func (o LookupResolverResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResolverResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the resource was last updated in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
func (o LookupResolverResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResolverResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupResolverResultOutput{})
}
