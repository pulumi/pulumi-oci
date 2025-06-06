// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Security Policy Deployments in Oracle Cloud Infrastructure Data Safe service.
//
// Retrieves a list of all security policy deployments in Data Safe.
//
// The ListSecurityPolicyDeployments operation returns only the security policy deployments in the specified `compartmentId`.
//
// The parameter `accessLevel` specifies whether to return only those compartments for which the
// requestor has INSPECT permissions on at least one resource directly
// or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
// Principal doesn't have access to even one of the child compartments. This is valid only when
// `compartmentIdInSubtree` is set to `true`.
//
// The parameter `compartmentIdInSubtree` applies when you perform ListSecurityPolicyDeployments on the
// `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
// To get a full list of all compartments and subcompartments in the tenancy (root compartment),
// set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datasafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datasafe.GetSecurityPolicyDeployments(ctx, &datasafe.GetSecurityPolicyDeploymentsArgs{
//				CompartmentId:              compartmentId,
//				AccessLevel:                pulumi.StringRef(securityPolicyDeploymentAccessLevel),
//				CompartmentIdInSubtree:     pulumi.BoolRef(securityPolicyDeploymentCompartmentIdInSubtree),
//				DisplayName:                pulumi.StringRef(securityPolicyDeploymentDisplayName),
//				SecurityPolicyDeploymentId: pulumi.StringRef(testSecurityPolicyDeployment.Id),
//				SecurityPolicyId:           pulumi.StringRef(testSecurityPolicy.Id),
//				State:                      pulumi.StringRef(securityPolicyDeploymentState),
//				TargetId:                   pulumi.StringRef(testTarget.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSecurityPolicyDeployments(ctx *pulumi.Context, args *GetSecurityPolicyDeploymentsArgs, opts ...pulumi.InvokeOption) (*GetSecurityPolicyDeploymentsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetSecurityPolicyDeploymentsResult
	err := ctx.Invoke("oci:DataSafe/getSecurityPolicyDeployments:getSecurityPolicyDeployments", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSecurityPolicyDeployments.
type GetSecurityPolicyDeploymentsArgs struct {
	// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
	AccessLevel *string `pulumi:"accessLevel"`
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId string `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree *bool `pulumi:"compartmentIdInSubtree"`
	// A filter to return only resources that match the specified display name.
	DisplayName *string                              `pulumi:"displayName"`
	Filters     []GetSecurityPolicyDeploymentsFilter `pulumi:"filters"`
	// An optional filter to return only resources that match the specified OCID of the security policy deployment resource.
	SecurityPolicyDeploymentId *string `pulumi:"securityPolicyDeploymentId"`
	// An optional filter to return only resources that match the specified OCID of the security policy resource.
	SecurityPolicyId *string `pulumi:"securityPolicyId"`
	// The current state of the security policy deployment.
	State *string `pulumi:"state"`
	// A filter to return only items related to a specific target OCID.
	TargetId *string `pulumi:"targetId"`
}

// A collection of values returned by getSecurityPolicyDeployments.
type GetSecurityPolicyDeploymentsResult struct {
	AccessLevel *string `pulumi:"accessLevel"`
	// The OCID of the compartment containing the security policy deployment.
	CompartmentId          string `pulumi:"compartmentId"`
	CompartmentIdInSubtree *bool  `pulumi:"compartmentIdInSubtree"`
	// The display name of the security policy deployment.
	DisplayName *string                              `pulumi:"displayName"`
	Filters     []GetSecurityPolicyDeploymentsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of security_policy_deployment_collection.
	SecurityPolicyDeploymentCollections []GetSecurityPolicyDeploymentsSecurityPolicyDeploymentCollection `pulumi:"securityPolicyDeploymentCollections"`
	SecurityPolicyDeploymentId          *string                                                          `pulumi:"securityPolicyDeploymentId"`
	// The OCID of the security policy corresponding to the security policy deployment.
	SecurityPolicyId *string `pulumi:"securityPolicyId"`
	// The current state of the security policy deployment.
	State *string `pulumi:"state"`
	// The OCID of the target where the security policy is deployed.
	TargetId *string `pulumi:"targetId"`
}

func GetSecurityPolicyDeploymentsOutput(ctx *pulumi.Context, args GetSecurityPolicyDeploymentsOutputArgs, opts ...pulumi.InvokeOption) GetSecurityPolicyDeploymentsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetSecurityPolicyDeploymentsResultOutput, error) {
			args := v.(GetSecurityPolicyDeploymentsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataSafe/getSecurityPolicyDeployments:getSecurityPolicyDeployments", args, GetSecurityPolicyDeploymentsResultOutput{}, options).(GetSecurityPolicyDeploymentsResultOutput), nil
		}).(GetSecurityPolicyDeploymentsResultOutput)
}

// A collection of arguments for invoking getSecurityPolicyDeployments.
type GetSecurityPolicyDeploymentsOutputArgs struct {
	// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
	AccessLevel pulumi.StringPtrInput `pulumi:"accessLevel"`
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree pulumi.BoolPtrInput `pulumi:"compartmentIdInSubtree"`
	// A filter to return only resources that match the specified display name.
	DisplayName pulumi.StringPtrInput                        `pulumi:"displayName"`
	Filters     GetSecurityPolicyDeploymentsFilterArrayInput `pulumi:"filters"`
	// An optional filter to return only resources that match the specified OCID of the security policy deployment resource.
	SecurityPolicyDeploymentId pulumi.StringPtrInput `pulumi:"securityPolicyDeploymentId"`
	// An optional filter to return only resources that match the specified OCID of the security policy resource.
	SecurityPolicyId pulumi.StringPtrInput `pulumi:"securityPolicyId"`
	// The current state of the security policy deployment.
	State pulumi.StringPtrInput `pulumi:"state"`
	// A filter to return only items related to a specific target OCID.
	TargetId pulumi.StringPtrInput `pulumi:"targetId"`
}

func (GetSecurityPolicyDeploymentsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecurityPolicyDeploymentsArgs)(nil)).Elem()
}

// A collection of values returned by getSecurityPolicyDeployments.
type GetSecurityPolicyDeploymentsResultOutput struct{ *pulumi.OutputState }

func (GetSecurityPolicyDeploymentsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecurityPolicyDeploymentsResult)(nil)).Elem()
}

func (o GetSecurityPolicyDeploymentsResultOutput) ToGetSecurityPolicyDeploymentsResultOutput() GetSecurityPolicyDeploymentsResultOutput {
	return o
}

func (o GetSecurityPolicyDeploymentsResultOutput) ToGetSecurityPolicyDeploymentsResultOutputWithContext(ctx context.Context) GetSecurityPolicyDeploymentsResultOutput {
	return o
}

func (o GetSecurityPolicyDeploymentsResultOutput) AccessLevel() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecurityPolicyDeploymentsResult) *string { return v.AccessLevel }).(pulumi.StringPtrOutput)
}

// The OCID of the compartment containing the security policy deployment.
func (o GetSecurityPolicyDeploymentsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecurityPolicyDeploymentsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetSecurityPolicyDeploymentsResultOutput) CompartmentIdInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetSecurityPolicyDeploymentsResult) *bool { return v.CompartmentIdInSubtree }).(pulumi.BoolPtrOutput)
}

// The display name of the security policy deployment.
func (o GetSecurityPolicyDeploymentsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecurityPolicyDeploymentsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetSecurityPolicyDeploymentsResultOutput) Filters() GetSecurityPolicyDeploymentsFilterArrayOutput {
	return o.ApplyT(func(v GetSecurityPolicyDeploymentsResult) []GetSecurityPolicyDeploymentsFilter { return v.Filters }).(GetSecurityPolicyDeploymentsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetSecurityPolicyDeploymentsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecurityPolicyDeploymentsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of security_policy_deployment_collection.
func (o GetSecurityPolicyDeploymentsResultOutput) SecurityPolicyDeploymentCollections() GetSecurityPolicyDeploymentsSecurityPolicyDeploymentCollectionArrayOutput {
	return o.ApplyT(func(v GetSecurityPolicyDeploymentsResult) []GetSecurityPolicyDeploymentsSecurityPolicyDeploymentCollection {
		return v.SecurityPolicyDeploymentCollections
	}).(GetSecurityPolicyDeploymentsSecurityPolicyDeploymentCollectionArrayOutput)
}

func (o GetSecurityPolicyDeploymentsResultOutput) SecurityPolicyDeploymentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecurityPolicyDeploymentsResult) *string { return v.SecurityPolicyDeploymentId }).(pulumi.StringPtrOutput)
}

// The OCID of the security policy corresponding to the security policy deployment.
func (o GetSecurityPolicyDeploymentsResultOutput) SecurityPolicyId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecurityPolicyDeploymentsResult) *string { return v.SecurityPolicyId }).(pulumi.StringPtrOutput)
}

// The current state of the security policy deployment.
func (o GetSecurityPolicyDeploymentsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecurityPolicyDeploymentsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The OCID of the target where the security policy is deployed.
func (o GetSecurityPolicyDeploymentsResultOutput) TargetId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecurityPolicyDeploymentsResult) *string { return v.TargetId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSecurityPolicyDeploymentsResultOutput{})
}
