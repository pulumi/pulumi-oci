// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package functions

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Applications in Oracle Cloud Infrastructure Functions service.
//
// Lists applications for a compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Functions"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Functions.GetApplications(ctx, &functions.GetApplicationsArgs{
//				CompartmentId: _var.Compartment_id,
//				DisplayName:   pulumi.StringRef(_var.Application_display_name),
//				Id:            pulumi.StringRef(_var.Application_id),
//				State:         pulumi.StringRef(_var.Application_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetApplications(ctx *pulumi.Context, args *GetApplicationsArgs, opts ...pulumi.InvokeOption) (*GetApplicationsResult, error) {
	var rv GetApplicationsResult
	err := ctx.Invoke("oci:Functions/getApplications:getApplications", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getApplications.
type GetApplicationsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this resource belongs.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only applications with display names that match the display name string. Matching is exact.
	DisplayName *string                 `pulumi:"displayName"`
	Filters     []GetApplicationsFilter `pulumi:"filters"`
	// A filter to return only applications with the specified OCID.
	Id *string `pulumi:"id"`
	// A filter to return only applications that match the lifecycle state in this parameter. Example: `Creating`
	State *string `pulumi:"state"`
}

// A collection of values returned by getApplications.
type GetApplicationsResult struct {
	// The list of applications.
	Applications []GetApplicationsApplication `pulumi:"applications"`
	// The OCID of the compartment that contains the application.
	CompartmentId string `pulumi:"compartmentId"`
	// The display name of the application. The display name is unique within the compartment containing the application.
	DisplayName *string                 `pulumi:"displayName"`
	Filters     []GetApplicationsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the application.
	Id *string `pulumi:"id"`
	// The current state of the application.
	State *string `pulumi:"state"`
}

func GetApplicationsOutput(ctx *pulumi.Context, args GetApplicationsOutputArgs, opts ...pulumi.InvokeOption) GetApplicationsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetApplicationsResult, error) {
			args := v.(GetApplicationsArgs)
			r, err := GetApplications(ctx, &args, opts...)
			var s GetApplicationsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetApplicationsResultOutput)
}

// A collection of arguments for invoking getApplications.
type GetApplicationsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this resource belongs.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only applications with display names that match the display name string. Matching is exact.
	DisplayName pulumi.StringPtrInput           `pulumi:"displayName"`
	Filters     GetApplicationsFilterArrayInput `pulumi:"filters"`
	// A filter to return only applications with the specified OCID.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A filter to return only applications that match the lifecycle state in this parameter. Example: `Creating`
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetApplicationsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetApplicationsArgs)(nil)).Elem()
}

// A collection of values returned by getApplications.
type GetApplicationsResultOutput struct{ *pulumi.OutputState }

func (GetApplicationsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetApplicationsResult)(nil)).Elem()
}

func (o GetApplicationsResultOutput) ToGetApplicationsResultOutput() GetApplicationsResultOutput {
	return o
}

func (o GetApplicationsResultOutput) ToGetApplicationsResultOutputWithContext(ctx context.Context) GetApplicationsResultOutput {
	return o
}

// The list of applications.
func (o GetApplicationsResultOutput) Applications() GetApplicationsApplicationArrayOutput {
	return o.ApplyT(func(v GetApplicationsResult) []GetApplicationsApplication { return v.Applications }).(GetApplicationsApplicationArrayOutput)
}

// The OCID of the compartment that contains the application.
func (o GetApplicationsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetApplicationsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The display name of the application. The display name is unique within the compartment containing the application.
func (o GetApplicationsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetApplicationsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetApplicationsResultOutput) Filters() GetApplicationsFilterArrayOutput {
	return o.ApplyT(func(v GetApplicationsResult) []GetApplicationsFilter { return v.Filters }).(GetApplicationsFilterArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the application.
func (o GetApplicationsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetApplicationsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The current state of the application.
func (o GetApplicationsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetApplicationsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetApplicationsResultOutput{})
}