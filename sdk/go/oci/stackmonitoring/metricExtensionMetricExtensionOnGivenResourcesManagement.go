// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package stackmonitoring

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This resource provides the Metric Extension Metric Extension On Given Resources Management resource in Oracle Cloud Infrastructure Stack Monitoring service.
//
// # Submits a request to enable matching metric extension Id for the given Resource IDs
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/StackMonitoring"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := StackMonitoring.NewMetricExtensionMetricExtensionOnGivenResourcesManagement(ctx, "testMetricExtensionMetricExtensionOnGivenResourcesManagement", &StackMonitoring.MetricExtensionMetricExtensionOnGivenResourcesManagementArgs{
//				MetricExtensionId:                     pulumi.Any(oci_stack_monitoring_metric_extension.Test_metric_extension.Id),
//				ResourceIds:                           pulumi.Any(_var.Metric_extension_metric_extension_on_given_resources_management_resource_ids),
//				EnableMetricExtensionOnGivenResources: pulumi.Any(_var.Enable_metric_extension_on_given_resources),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
type MetricExtensionMetricExtensionOnGivenResourcesManagement struct {
	pulumi.CustomResourceState

	// (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	EnableMetricExtensionOnGivenResources pulumi.BoolOutput `pulumi:"enableMetricExtensionOnGivenResources"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the metric extension resource.
	MetricExtensionId pulumi.StringOutput `pulumi:"metricExtensionId"`
	// List of Resource IDs [OCIDs]. Currently, supports only one resource id per request.
	ResourceIds pulumi.StringOutput `pulumi:"resourceIds"`
}

// NewMetricExtensionMetricExtensionOnGivenResourcesManagement registers a new resource with the given unique name, arguments, and options.
func NewMetricExtensionMetricExtensionOnGivenResourcesManagement(ctx *pulumi.Context,
	name string, args *MetricExtensionMetricExtensionOnGivenResourcesManagementArgs, opts ...pulumi.ResourceOption) (*MetricExtensionMetricExtensionOnGivenResourcesManagement, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.EnableMetricExtensionOnGivenResources == nil {
		return nil, errors.New("invalid value for required argument 'EnableMetricExtensionOnGivenResources'")
	}
	if args.MetricExtensionId == nil {
		return nil, errors.New("invalid value for required argument 'MetricExtensionId'")
	}
	if args.ResourceIds == nil {
		return nil, errors.New("invalid value for required argument 'ResourceIds'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource MetricExtensionMetricExtensionOnGivenResourcesManagement
	err := ctx.RegisterResource("oci:StackMonitoring/metricExtensionMetricExtensionOnGivenResourcesManagement:MetricExtensionMetricExtensionOnGivenResourcesManagement", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetMetricExtensionMetricExtensionOnGivenResourcesManagement gets an existing MetricExtensionMetricExtensionOnGivenResourcesManagement resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetMetricExtensionMetricExtensionOnGivenResourcesManagement(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *MetricExtensionMetricExtensionOnGivenResourcesManagementState, opts ...pulumi.ResourceOption) (*MetricExtensionMetricExtensionOnGivenResourcesManagement, error) {
	var resource MetricExtensionMetricExtensionOnGivenResourcesManagement
	err := ctx.ReadResource("oci:StackMonitoring/metricExtensionMetricExtensionOnGivenResourcesManagement:MetricExtensionMetricExtensionOnGivenResourcesManagement", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering MetricExtensionMetricExtensionOnGivenResourcesManagement resources.
type metricExtensionMetricExtensionOnGivenResourcesManagementState struct {
	// (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	EnableMetricExtensionOnGivenResources *bool `pulumi:"enableMetricExtensionOnGivenResources"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the metric extension resource.
	MetricExtensionId *string `pulumi:"metricExtensionId"`
	// List of Resource IDs [OCIDs]. Currently, supports only one resource id per request.
	ResourceIds *string `pulumi:"resourceIds"`
}

type MetricExtensionMetricExtensionOnGivenResourcesManagementState struct {
	// (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	EnableMetricExtensionOnGivenResources pulumi.BoolPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the metric extension resource.
	MetricExtensionId pulumi.StringPtrInput
	// List of Resource IDs [OCIDs]. Currently, supports only one resource id per request.
	ResourceIds pulumi.StringPtrInput
}

func (MetricExtensionMetricExtensionOnGivenResourcesManagementState) ElementType() reflect.Type {
	return reflect.TypeOf((*metricExtensionMetricExtensionOnGivenResourcesManagementState)(nil)).Elem()
}

type metricExtensionMetricExtensionOnGivenResourcesManagementArgs struct {
	// (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	EnableMetricExtensionOnGivenResources bool `pulumi:"enableMetricExtensionOnGivenResources"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the metric extension resource.
	MetricExtensionId string `pulumi:"metricExtensionId"`
	// List of Resource IDs [OCIDs]. Currently, supports only one resource id per request.
	ResourceIds string `pulumi:"resourceIds"`
}

// The set of arguments for constructing a MetricExtensionMetricExtensionOnGivenResourcesManagement resource.
type MetricExtensionMetricExtensionOnGivenResourcesManagementArgs struct {
	// (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	EnableMetricExtensionOnGivenResources pulumi.BoolInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the metric extension resource.
	MetricExtensionId pulumi.StringInput
	// List of Resource IDs [OCIDs]. Currently, supports only one resource id per request.
	ResourceIds pulumi.StringInput
}

func (MetricExtensionMetricExtensionOnGivenResourcesManagementArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*metricExtensionMetricExtensionOnGivenResourcesManagementArgs)(nil)).Elem()
}

type MetricExtensionMetricExtensionOnGivenResourcesManagementInput interface {
	pulumi.Input

	ToMetricExtensionMetricExtensionOnGivenResourcesManagementOutput() MetricExtensionMetricExtensionOnGivenResourcesManagementOutput
	ToMetricExtensionMetricExtensionOnGivenResourcesManagementOutputWithContext(ctx context.Context) MetricExtensionMetricExtensionOnGivenResourcesManagementOutput
}

func (*MetricExtensionMetricExtensionOnGivenResourcesManagement) ElementType() reflect.Type {
	return reflect.TypeOf((**MetricExtensionMetricExtensionOnGivenResourcesManagement)(nil)).Elem()
}

func (i *MetricExtensionMetricExtensionOnGivenResourcesManagement) ToMetricExtensionMetricExtensionOnGivenResourcesManagementOutput() MetricExtensionMetricExtensionOnGivenResourcesManagementOutput {
	return i.ToMetricExtensionMetricExtensionOnGivenResourcesManagementOutputWithContext(context.Background())
}

func (i *MetricExtensionMetricExtensionOnGivenResourcesManagement) ToMetricExtensionMetricExtensionOnGivenResourcesManagementOutputWithContext(ctx context.Context) MetricExtensionMetricExtensionOnGivenResourcesManagementOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MetricExtensionMetricExtensionOnGivenResourcesManagementOutput)
}

func (i *MetricExtensionMetricExtensionOnGivenResourcesManagement) ToOutput(ctx context.Context) pulumix.Output[*MetricExtensionMetricExtensionOnGivenResourcesManagement] {
	return pulumix.Output[*MetricExtensionMetricExtensionOnGivenResourcesManagement]{
		OutputState: i.ToMetricExtensionMetricExtensionOnGivenResourcesManagementOutputWithContext(ctx).OutputState,
	}
}

// MetricExtensionMetricExtensionOnGivenResourcesManagementArrayInput is an input type that accepts MetricExtensionMetricExtensionOnGivenResourcesManagementArray and MetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput values.
// You can construct a concrete instance of `MetricExtensionMetricExtensionOnGivenResourcesManagementArrayInput` via:
//
//	MetricExtensionMetricExtensionOnGivenResourcesManagementArray{ MetricExtensionMetricExtensionOnGivenResourcesManagementArgs{...} }
type MetricExtensionMetricExtensionOnGivenResourcesManagementArrayInput interface {
	pulumi.Input

	ToMetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput() MetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput
	ToMetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutputWithContext(context.Context) MetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput
}

type MetricExtensionMetricExtensionOnGivenResourcesManagementArray []MetricExtensionMetricExtensionOnGivenResourcesManagementInput

func (MetricExtensionMetricExtensionOnGivenResourcesManagementArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*MetricExtensionMetricExtensionOnGivenResourcesManagement)(nil)).Elem()
}

func (i MetricExtensionMetricExtensionOnGivenResourcesManagementArray) ToMetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput() MetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput {
	return i.ToMetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutputWithContext(context.Background())
}

func (i MetricExtensionMetricExtensionOnGivenResourcesManagementArray) ToMetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutputWithContext(ctx context.Context) MetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput)
}

func (i MetricExtensionMetricExtensionOnGivenResourcesManagementArray) ToOutput(ctx context.Context) pulumix.Output[[]*MetricExtensionMetricExtensionOnGivenResourcesManagement] {
	return pulumix.Output[[]*MetricExtensionMetricExtensionOnGivenResourcesManagement]{
		OutputState: i.ToMetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutputWithContext(ctx).OutputState,
	}
}

// MetricExtensionMetricExtensionOnGivenResourcesManagementMapInput is an input type that accepts MetricExtensionMetricExtensionOnGivenResourcesManagementMap and MetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput values.
// You can construct a concrete instance of `MetricExtensionMetricExtensionOnGivenResourcesManagementMapInput` via:
//
//	MetricExtensionMetricExtensionOnGivenResourcesManagementMap{ "key": MetricExtensionMetricExtensionOnGivenResourcesManagementArgs{...} }
type MetricExtensionMetricExtensionOnGivenResourcesManagementMapInput interface {
	pulumi.Input

	ToMetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput() MetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput
	ToMetricExtensionMetricExtensionOnGivenResourcesManagementMapOutputWithContext(context.Context) MetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput
}

type MetricExtensionMetricExtensionOnGivenResourcesManagementMap map[string]MetricExtensionMetricExtensionOnGivenResourcesManagementInput

func (MetricExtensionMetricExtensionOnGivenResourcesManagementMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*MetricExtensionMetricExtensionOnGivenResourcesManagement)(nil)).Elem()
}

func (i MetricExtensionMetricExtensionOnGivenResourcesManagementMap) ToMetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput() MetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput {
	return i.ToMetricExtensionMetricExtensionOnGivenResourcesManagementMapOutputWithContext(context.Background())
}

func (i MetricExtensionMetricExtensionOnGivenResourcesManagementMap) ToMetricExtensionMetricExtensionOnGivenResourcesManagementMapOutputWithContext(ctx context.Context) MetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput)
}

func (i MetricExtensionMetricExtensionOnGivenResourcesManagementMap) ToOutput(ctx context.Context) pulumix.Output[map[string]*MetricExtensionMetricExtensionOnGivenResourcesManagement] {
	return pulumix.Output[map[string]*MetricExtensionMetricExtensionOnGivenResourcesManagement]{
		OutputState: i.ToMetricExtensionMetricExtensionOnGivenResourcesManagementMapOutputWithContext(ctx).OutputState,
	}
}

type MetricExtensionMetricExtensionOnGivenResourcesManagementOutput struct{ *pulumi.OutputState }

func (MetricExtensionMetricExtensionOnGivenResourcesManagementOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**MetricExtensionMetricExtensionOnGivenResourcesManagement)(nil)).Elem()
}

func (o MetricExtensionMetricExtensionOnGivenResourcesManagementOutput) ToMetricExtensionMetricExtensionOnGivenResourcesManagementOutput() MetricExtensionMetricExtensionOnGivenResourcesManagementOutput {
	return o
}

func (o MetricExtensionMetricExtensionOnGivenResourcesManagementOutput) ToMetricExtensionMetricExtensionOnGivenResourcesManagementOutputWithContext(ctx context.Context) MetricExtensionMetricExtensionOnGivenResourcesManagementOutput {
	return o
}

func (o MetricExtensionMetricExtensionOnGivenResourcesManagementOutput) ToOutput(ctx context.Context) pulumix.Output[*MetricExtensionMetricExtensionOnGivenResourcesManagement] {
	return pulumix.Output[*MetricExtensionMetricExtensionOnGivenResourcesManagement]{
		OutputState: o.OutputState,
	}
}

// (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o MetricExtensionMetricExtensionOnGivenResourcesManagementOutput) EnableMetricExtensionOnGivenResources() pulumi.BoolOutput {
	return o.ApplyT(func(v *MetricExtensionMetricExtensionOnGivenResourcesManagement) pulumi.BoolOutput {
		return v.EnableMetricExtensionOnGivenResources
	}).(pulumi.BoolOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the metric extension resource.
func (o MetricExtensionMetricExtensionOnGivenResourcesManagementOutput) MetricExtensionId() pulumi.StringOutput {
	return o.ApplyT(func(v *MetricExtensionMetricExtensionOnGivenResourcesManagement) pulumi.StringOutput {
		return v.MetricExtensionId
	}).(pulumi.StringOutput)
}

// List of Resource IDs [OCIDs]. Currently, supports only one resource id per request.
func (o MetricExtensionMetricExtensionOnGivenResourcesManagementOutput) ResourceIds() pulumi.StringOutput {
	return o.ApplyT(func(v *MetricExtensionMetricExtensionOnGivenResourcesManagement) pulumi.StringOutput {
		return v.ResourceIds
	}).(pulumi.StringOutput)
}

type MetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput struct{ *pulumi.OutputState }

func (MetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*MetricExtensionMetricExtensionOnGivenResourcesManagement)(nil)).Elem()
}

func (o MetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput) ToMetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput() MetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput {
	return o
}

func (o MetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput) ToMetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutputWithContext(ctx context.Context) MetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput {
	return o
}

func (o MetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput) ToOutput(ctx context.Context) pulumix.Output[[]*MetricExtensionMetricExtensionOnGivenResourcesManagement] {
	return pulumix.Output[[]*MetricExtensionMetricExtensionOnGivenResourcesManagement]{
		OutputState: o.OutputState,
	}
}

func (o MetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput) Index(i pulumi.IntInput) MetricExtensionMetricExtensionOnGivenResourcesManagementOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *MetricExtensionMetricExtensionOnGivenResourcesManagement {
		return vs[0].([]*MetricExtensionMetricExtensionOnGivenResourcesManagement)[vs[1].(int)]
	}).(MetricExtensionMetricExtensionOnGivenResourcesManagementOutput)
}

type MetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput struct{ *pulumi.OutputState }

func (MetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*MetricExtensionMetricExtensionOnGivenResourcesManagement)(nil)).Elem()
}

func (o MetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput) ToMetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput() MetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput {
	return o
}

func (o MetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput) ToMetricExtensionMetricExtensionOnGivenResourcesManagementMapOutputWithContext(ctx context.Context) MetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput {
	return o
}

func (o MetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput) ToOutput(ctx context.Context) pulumix.Output[map[string]*MetricExtensionMetricExtensionOnGivenResourcesManagement] {
	return pulumix.Output[map[string]*MetricExtensionMetricExtensionOnGivenResourcesManagement]{
		OutputState: o.OutputState,
	}
}

func (o MetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput) MapIndex(k pulumi.StringInput) MetricExtensionMetricExtensionOnGivenResourcesManagementOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *MetricExtensionMetricExtensionOnGivenResourcesManagement {
		return vs[0].(map[string]*MetricExtensionMetricExtensionOnGivenResourcesManagement)[vs[1].(string)]
	}).(MetricExtensionMetricExtensionOnGivenResourcesManagementOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*MetricExtensionMetricExtensionOnGivenResourcesManagementInput)(nil)).Elem(), &MetricExtensionMetricExtensionOnGivenResourcesManagement{})
	pulumi.RegisterInputType(reflect.TypeOf((*MetricExtensionMetricExtensionOnGivenResourcesManagementArrayInput)(nil)).Elem(), MetricExtensionMetricExtensionOnGivenResourcesManagementArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*MetricExtensionMetricExtensionOnGivenResourcesManagementMapInput)(nil)).Elem(), MetricExtensionMetricExtensionOnGivenResourcesManagementMap{})
	pulumi.RegisterOutputType(MetricExtensionMetricExtensionOnGivenResourcesManagementOutput{})
	pulumi.RegisterOutputType(MetricExtensionMetricExtensionOnGivenResourcesManagementArrayOutput{})
	pulumi.RegisterOutputType(MetricExtensionMetricExtensionOnGivenResourcesManagementMapOutput{})
}