// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package limits

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Resource Availability resource in Oracle Cloud Infrastructure Limits service.
//
// For a given compartmentId, resource limit name, and scope, returns the following:
//   - The number of available resources associated with the given limit.
//   - The usage in the selected compartment for the given limit.
//     Note that not all resource limits support this API. If the value is not available, the API returns a 404 response.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Limits"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Limits.GetResourceAvailability(ctx, &limits.GetResourceAvailabilityArgs{
//				CompartmentId:      _var.Tenancy_ocid,
//				LimitName:          _var.Resource_availability_limit_name,
//				ServiceName:        oci_limits_service.Test_service.Name,
//				AvailabilityDomain: pulumi.StringRef(_var.Resource_availability_availability_domain),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetResourceAvailability(ctx *pulumi.Context, args *GetResourceAvailabilityArgs, opts ...pulumi.InvokeOption) (*GetResourceAvailabilityResult, error) {
	var rv GetResourceAvailabilityResult
	err := ctx.Invoke("oci:Limits/getResourceAvailability:getResourceAvailability", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getResourceAvailability.
type GetResourceAvailabilityArgs struct {
	// This field is mandatory if the scopeType of the target resource limit is AD. Otherwise, this field should be omitted. If the above requirements are not met, the API returns a 400 - InvalidParameter response.
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The OCID of the compartment for which data is being fetched.
	CompartmentId string `pulumi:"compartmentId"`
	// The limit name for which to fetch the data.
	LimitName string `pulumi:"limitName"`
	// The service name of the target quota.
	ServiceName string `pulumi:"serviceName"`
}

// A collection of values returned by getResourceAvailability.
type GetResourceAvailabilityResult struct {
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The count of available resources. To support resources with fractional counts, the field rounds down to the nearest integer.
	Available     string `pulumi:"available"`
	CompartmentId string `pulumi:"compartmentId"`
	// The effective quota value for the given compartment. This field is only present if there is a current quota policy affecting the current resource in the target region or availability domain.
	EffectiveQuotaValue float64 `pulumi:"effectiveQuotaValue"`
	// The most accurate count of available resources.
	FractionalAvailability float64 `pulumi:"fractionalAvailability"`
	// The current most accurate usage in the given compartment.
	FractionalUsage float64 `pulumi:"fractionalUsage"`
	// The provider-assigned unique ID for this managed resource.
	Id          string `pulumi:"id"`
	LimitName   string `pulumi:"limitName"`
	ServiceName string `pulumi:"serviceName"`
	// The current usage in the given compartment. To support resources with fractional counts, the field rounds up to the nearest integer.
	Used string `pulumi:"used"`
}

func GetResourceAvailabilityOutput(ctx *pulumi.Context, args GetResourceAvailabilityOutputArgs, opts ...pulumi.InvokeOption) GetResourceAvailabilityResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetResourceAvailabilityResult, error) {
			args := v.(GetResourceAvailabilityArgs)
			r, err := GetResourceAvailability(ctx, &args, opts...)
			var s GetResourceAvailabilityResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetResourceAvailabilityResultOutput)
}

// A collection of arguments for invoking getResourceAvailability.
type GetResourceAvailabilityOutputArgs struct {
	// This field is mandatory if the scopeType of the target resource limit is AD. Otherwise, this field should be omitted. If the above requirements are not met, the API returns a 400 - InvalidParameter response.
	AvailabilityDomain pulumi.StringPtrInput `pulumi:"availabilityDomain"`
	// The OCID of the compartment for which data is being fetched.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The limit name for which to fetch the data.
	LimitName pulumi.StringInput `pulumi:"limitName"`
	// The service name of the target quota.
	ServiceName pulumi.StringInput `pulumi:"serviceName"`
}

func (GetResourceAvailabilityOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetResourceAvailabilityArgs)(nil)).Elem()
}

// A collection of values returned by getResourceAvailability.
type GetResourceAvailabilityResultOutput struct{ *pulumi.OutputState }

func (GetResourceAvailabilityResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetResourceAvailabilityResult)(nil)).Elem()
}

func (o GetResourceAvailabilityResultOutput) ToGetResourceAvailabilityResultOutput() GetResourceAvailabilityResultOutput {
	return o
}

func (o GetResourceAvailabilityResultOutput) ToGetResourceAvailabilityResultOutputWithContext(ctx context.Context) GetResourceAvailabilityResultOutput {
	return o
}

func (o GetResourceAvailabilityResultOutput) AvailabilityDomain() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetResourceAvailabilityResult) *string { return v.AvailabilityDomain }).(pulumi.StringPtrOutput)
}

// The count of available resources. To support resources with fractional counts, the field rounds down to the nearest integer.
func (o GetResourceAvailabilityResultOutput) Available() pulumi.StringOutput {
	return o.ApplyT(func(v GetResourceAvailabilityResult) string { return v.Available }).(pulumi.StringOutput)
}

func (o GetResourceAvailabilityResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetResourceAvailabilityResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The effective quota value for the given compartment. This field is only present if there is a current quota policy affecting the current resource in the target region or availability domain.
func (o GetResourceAvailabilityResultOutput) EffectiveQuotaValue() pulumi.Float64Output {
	return o.ApplyT(func(v GetResourceAvailabilityResult) float64 { return v.EffectiveQuotaValue }).(pulumi.Float64Output)
}

// The most accurate count of available resources.
func (o GetResourceAvailabilityResultOutput) FractionalAvailability() pulumi.Float64Output {
	return o.ApplyT(func(v GetResourceAvailabilityResult) float64 { return v.FractionalAvailability }).(pulumi.Float64Output)
}

// The current most accurate usage in the given compartment.
func (o GetResourceAvailabilityResultOutput) FractionalUsage() pulumi.Float64Output {
	return o.ApplyT(func(v GetResourceAvailabilityResult) float64 { return v.FractionalUsage }).(pulumi.Float64Output)
}

// The provider-assigned unique ID for this managed resource.
func (o GetResourceAvailabilityResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetResourceAvailabilityResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetResourceAvailabilityResultOutput) LimitName() pulumi.StringOutput {
	return o.ApplyT(func(v GetResourceAvailabilityResult) string { return v.LimitName }).(pulumi.StringOutput)
}

func (o GetResourceAvailabilityResultOutput) ServiceName() pulumi.StringOutput {
	return o.ApplyT(func(v GetResourceAvailabilityResult) string { return v.ServiceName }).(pulumi.StringOutput)
}

// The current usage in the given compartment. To support resources with fractional counts, the field rounds up to the nearest integer.
func (o GetResourceAvailabilityResultOutput) Used() pulumi.StringOutput {
	return o.ApplyT(func(v GetResourceAvailabilityResult) string { return v.Used }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetResourceAvailabilityResultOutput{})
}