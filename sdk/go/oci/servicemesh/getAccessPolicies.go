// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package servicemesh

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v2/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Access Policies in Oracle Cloud Infrastructure Service Mesh service.
//
// Returns a list of AccessPolicy objects.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v2/go/oci/servicemesh"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := servicemesh.GetAccessPolicies(ctx, &servicemesh.GetAccessPoliciesArgs{
//				CompartmentId: compartmentId,
//				Id:            pulumi.StringRef(accessPolicyId),
//				MeshId:        pulumi.StringRef(testMesh.Id),
//				Name:          pulumi.StringRef(accessPolicyName),
//				State:         pulumi.StringRef(accessPolicyState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetAccessPolicies(ctx *pulumi.Context, args *GetAccessPoliciesArgs, opts ...pulumi.InvokeOption) (*GetAccessPoliciesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetAccessPoliciesResult
	err := ctx.Invoke("oci:ServiceMesh/getAccessPolicies:getAccessPolicies", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAccessPolicies.
type GetAccessPoliciesArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId string                    `pulumi:"compartmentId"`
	Filters       []GetAccessPoliciesFilter `pulumi:"filters"`
	// Unique AccessPolicy identifier.
	Id *string `pulumi:"id"`
	// Unique Mesh identifier.
	MeshId *string `pulumi:"meshId"`
	// A filter to return only resources that match the entire name given.
	Name *string `pulumi:"name"`
	// A filter to return only resources that match the life cycle state given.
	State *string `pulumi:"state"`
}

// A collection of values returned by getAccessPolicies.
type GetAccessPoliciesResult struct {
	// The list of access_policy_collection.
	AccessPolicyCollections []GetAccessPoliciesAccessPolicyCollection `pulumi:"accessPolicyCollections"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string                    `pulumi:"compartmentId"`
	Filters       []GetAccessPoliciesFilter `pulumi:"filters"`
	// Unique identifier that is immutable on creation.
	Id *string `pulumi:"id"`
	// The OCID of the service mesh in which this access policy is created.
	MeshId *string `pulumi:"meshId"`
	// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
	Name *string `pulumi:"name"`
	// The current state of the Resource.
	State *string `pulumi:"state"`
}

func GetAccessPoliciesOutput(ctx *pulumi.Context, args GetAccessPoliciesOutputArgs, opts ...pulumi.InvokeOption) GetAccessPoliciesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetAccessPoliciesResultOutput, error) {
			args := v.(GetAccessPoliciesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ServiceMesh/getAccessPolicies:getAccessPolicies", args, GetAccessPoliciesResultOutput{}, options).(GetAccessPoliciesResultOutput), nil
		}).(GetAccessPoliciesResultOutput)
}

// A collection of arguments for invoking getAccessPolicies.
type GetAccessPoliciesOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput                `pulumi:"compartmentId"`
	Filters       GetAccessPoliciesFilterArrayInput `pulumi:"filters"`
	// Unique AccessPolicy identifier.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// Unique Mesh identifier.
	MeshId pulumi.StringPtrInput `pulumi:"meshId"`
	// A filter to return only resources that match the entire name given.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// A filter to return only resources that match the life cycle state given.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetAccessPoliciesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAccessPoliciesArgs)(nil)).Elem()
}

// A collection of values returned by getAccessPolicies.
type GetAccessPoliciesResultOutput struct{ *pulumi.OutputState }

func (GetAccessPoliciesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAccessPoliciesResult)(nil)).Elem()
}

func (o GetAccessPoliciesResultOutput) ToGetAccessPoliciesResultOutput() GetAccessPoliciesResultOutput {
	return o
}

func (o GetAccessPoliciesResultOutput) ToGetAccessPoliciesResultOutputWithContext(ctx context.Context) GetAccessPoliciesResultOutput {
	return o
}

// The list of access_policy_collection.
func (o GetAccessPoliciesResultOutput) AccessPolicyCollections() GetAccessPoliciesAccessPolicyCollectionArrayOutput {
	return o.ApplyT(func(v GetAccessPoliciesResult) []GetAccessPoliciesAccessPolicyCollection {
		return v.AccessPolicyCollections
	}).(GetAccessPoliciesAccessPolicyCollectionArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o GetAccessPoliciesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetAccessPoliciesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetAccessPoliciesResultOutput) Filters() GetAccessPoliciesFilterArrayOutput {
	return o.ApplyT(func(v GetAccessPoliciesResult) []GetAccessPoliciesFilter { return v.Filters }).(GetAccessPoliciesFilterArrayOutput)
}

// Unique identifier that is immutable on creation.
func (o GetAccessPoliciesResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAccessPoliciesResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The OCID of the service mesh in which this access policy is created.
func (o GetAccessPoliciesResultOutput) MeshId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAccessPoliciesResult) *string { return v.MeshId }).(pulumi.StringPtrOutput)
}

// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
func (o GetAccessPoliciesResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAccessPoliciesResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The current state of the Resource.
func (o GetAccessPoliciesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAccessPoliciesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetAccessPoliciesResultOutput{})
}
