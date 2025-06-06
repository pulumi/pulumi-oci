// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package goldengate

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Connection Assignments in Oracle Cloud Infrastructure Golden Gate service.
//
// Lists the Connection Assignments in the compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/goldengate"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := goldengate.GetConnectionAssignments(ctx, &goldengate.GetConnectionAssignmentsArgs{
//				CompartmentId: compartmentId,
//				ConnectionId:  pulumi.StringRef(testConnection.Id),
//				DeploymentId:  pulumi.StringRef(testDeployment.Id),
//				Name:          pulumi.StringRef(connectionAssignmentName),
//				State:         pulumi.StringRef(connectionAssignmentState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetConnectionAssignments(ctx *pulumi.Context, args *GetConnectionAssignmentsArgs, opts ...pulumi.InvokeOption) (*GetConnectionAssignmentsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetConnectionAssignmentsResult
	err := ctx.Invoke("oci:GoldenGate/getConnectionAssignments:getConnectionAssignments", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getConnectionAssignments.
type GetConnectionAssignmentsArgs struct {
	// The OCID of the compartment that contains the work request. Work requests should be scoped  to the same compartment as the resource the work request affects. If the work request concerns  multiple resources, and those resources are not in the same compartment, it is up to the service team  to pick the primary resource whose compartment should be used.
	CompartmentId string `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the connection.
	ConnectionId *string `pulumi:"connectionId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment in which to list resources.
	DeploymentId *string                          `pulumi:"deploymentId"`
	Filters      []GetConnectionAssignmentsFilter `pulumi:"filters"`
	// The name of the connection in the assignment (aliasName).
	Name *string `pulumi:"name"`
	// A filter to return only connection assignments having the 'lifecycleState' given.
	State *string `pulumi:"state"`
}

// A collection of values returned by getConnectionAssignments.
type GetConnectionAssignmentsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
	CompartmentId string `pulumi:"compartmentId"`
	// The list of connection_assignment_collection.
	ConnectionAssignmentCollections []GetConnectionAssignmentsConnectionAssignmentCollection `pulumi:"connectionAssignmentCollections"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the connection being referenced.
	ConnectionId *string `pulumi:"connectionId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
	DeploymentId *string                          `pulumi:"deploymentId"`
	Filters      []GetConnectionAssignmentsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id   string  `pulumi:"id"`
	Name *string `pulumi:"name"`
	// Possible lifecycle states for connection assignments.
	State *string `pulumi:"state"`
}

func GetConnectionAssignmentsOutput(ctx *pulumi.Context, args GetConnectionAssignmentsOutputArgs, opts ...pulumi.InvokeOption) GetConnectionAssignmentsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetConnectionAssignmentsResultOutput, error) {
			args := v.(GetConnectionAssignmentsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:GoldenGate/getConnectionAssignments:getConnectionAssignments", args, GetConnectionAssignmentsResultOutput{}, options).(GetConnectionAssignmentsResultOutput), nil
		}).(GetConnectionAssignmentsResultOutput)
}

// A collection of arguments for invoking getConnectionAssignments.
type GetConnectionAssignmentsOutputArgs struct {
	// The OCID of the compartment that contains the work request. Work requests should be scoped  to the same compartment as the resource the work request affects. If the work request concerns  multiple resources, and those resources are not in the same compartment, it is up to the service team  to pick the primary resource whose compartment should be used.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the connection.
	ConnectionId pulumi.StringPtrInput `pulumi:"connectionId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment in which to list resources.
	DeploymentId pulumi.StringPtrInput                    `pulumi:"deploymentId"`
	Filters      GetConnectionAssignmentsFilterArrayInput `pulumi:"filters"`
	// The name of the connection in the assignment (aliasName).
	Name pulumi.StringPtrInput `pulumi:"name"`
	// A filter to return only connection assignments having the 'lifecycleState' given.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetConnectionAssignmentsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetConnectionAssignmentsArgs)(nil)).Elem()
}

// A collection of values returned by getConnectionAssignments.
type GetConnectionAssignmentsResultOutput struct{ *pulumi.OutputState }

func (GetConnectionAssignmentsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetConnectionAssignmentsResult)(nil)).Elem()
}

func (o GetConnectionAssignmentsResultOutput) ToGetConnectionAssignmentsResultOutput() GetConnectionAssignmentsResultOutput {
	return o
}

func (o GetConnectionAssignmentsResultOutput) ToGetConnectionAssignmentsResultOutputWithContext(ctx context.Context) GetConnectionAssignmentsResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
func (o GetConnectionAssignmentsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetConnectionAssignmentsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The list of connection_assignment_collection.
func (o GetConnectionAssignmentsResultOutput) ConnectionAssignmentCollections() GetConnectionAssignmentsConnectionAssignmentCollectionArrayOutput {
	return o.ApplyT(func(v GetConnectionAssignmentsResult) []GetConnectionAssignmentsConnectionAssignmentCollection {
		return v.ConnectionAssignmentCollections
	}).(GetConnectionAssignmentsConnectionAssignmentCollectionArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the connection being referenced.
func (o GetConnectionAssignmentsResultOutput) ConnectionId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetConnectionAssignmentsResult) *string { return v.ConnectionId }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
func (o GetConnectionAssignmentsResultOutput) DeploymentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetConnectionAssignmentsResult) *string { return v.DeploymentId }).(pulumi.StringPtrOutput)
}

func (o GetConnectionAssignmentsResultOutput) Filters() GetConnectionAssignmentsFilterArrayOutput {
	return o.ApplyT(func(v GetConnectionAssignmentsResult) []GetConnectionAssignmentsFilter { return v.Filters }).(GetConnectionAssignmentsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetConnectionAssignmentsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetConnectionAssignmentsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetConnectionAssignmentsResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetConnectionAssignmentsResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// Possible lifecycle states for connection assignments.
func (o GetConnectionAssignmentsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetConnectionAssignmentsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetConnectionAssignmentsResultOutput{})
}
