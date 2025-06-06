// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Externalpluggabledatabases Stack Monitoring resource in Oracle Cloud Infrastructure Database service.
//
// Enable Stack Monitoring for the external pluggable database.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := database.NewExternalPluggableDatabasesStackMonitoring(ctx, "test_externalpluggabledatabases_stack_monitoring", &database.ExternalPluggableDatabasesStackMonitoringArgs{
//				ExternalDatabaseConnectorId: pulumi.Any(testExternalDatabaseConnector.Id),
//				ExternalPluggableDatabaseId: pulumi.Any(testExternalPluggableDatabase.Id),
//				EnableStackMonitoring:       pulumi.Bool(true),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// Import is not supported for this resource.
type ExternalPluggableDatabasesStackMonitoring struct {
	pulumi.CustomResourceState

	// (Updatable) Enabling Stack Monitoring on External Pluggable Databases . Requires boolean value "true" or "false".
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	EnableStackMonitoring pulumi.BoolOutput `pulumi:"enableStackMonitoring"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
	ExternalDatabaseConnectorId pulumi.StringOutput `pulumi:"externalDatabaseConnectorId"`
	// The ExternalPluggableDatabaseId [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ExternalPluggableDatabaseId pulumi.StringOutput `pulumi:"externalPluggableDatabaseId"`
}

// NewExternalPluggableDatabasesStackMonitoring registers a new resource with the given unique name, arguments, and options.
func NewExternalPluggableDatabasesStackMonitoring(ctx *pulumi.Context,
	name string, args *ExternalPluggableDatabasesStackMonitoringArgs, opts ...pulumi.ResourceOption) (*ExternalPluggableDatabasesStackMonitoring, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.EnableStackMonitoring == nil {
		return nil, errors.New("invalid value for required argument 'EnableStackMonitoring'")
	}
	if args.ExternalDatabaseConnectorId == nil {
		return nil, errors.New("invalid value for required argument 'ExternalDatabaseConnectorId'")
	}
	if args.ExternalPluggableDatabaseId == nil {
		return nil, errors.New("invalid value for required argument 'ExternalPluggableDatabaseId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ExternalPluggableDatabasesStackMonitoring
	err := ctx.RegisterResource("oci:Database/externalPluggableDatabasesStackMonitoring:ExternalPluggableDatabasesStackMonitoring", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetExternalPluggableDatabasesStackMonitoring gets an existing ExternalPluggableDatabasesStackMonitoring resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetExternalPluggableDatabasesStackMonitoring(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ExternalPluggableDatabasesStackMonitoringState, opts ...pulumi.ResourceOption) (*ExternalPluggableDatabasesStackMonitoring, error) {
	var resource ExternalPluggableDatabasesStackMonitoring
	err := ctx.ReadResource("oci:Database/externalPluggableDatabasesStackMonitoring:ExternalPluggableDatabasesStackMonitoring", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ExternalPluggableDatabasesStackMonitoring resources.
type externalPluggableDatabasesStackMonitoringState struct {
	// (Updatable) Enabling Stack Monitoring on External Pluggable Databases . Requires boolean value "true" or "false".
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	EnableStackMonitoring *bool `pulumi:"enableStackMonitoring"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
	ExternalDatabaseConnectorId *string `pulumi:"externalDatabaseConnectorId"`
	// The ExternalPluggableDatabaseId [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ExternalPluggableDatabaseId *string `pulumi:"externalPluggableDatabaseId"`
}

type ExternalPluggableDatabasesStackMonitoringState struct {
	// (Updatable) Enabling Stack Monitoring on External Pluggable Databases . Requires boolean value "true" or "false".
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	EnableStackMonitoring pulumi.BoolPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
	ExternalDatabaseConnectorId pulumi.StringPtrInput
	// The ExternalPluggableDatabaseId [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ExternalPluggableDatabaseId pulumi.StringPtrInput
}

func (ExternalPluggableDatabasesStackMonitoringState) ElementType() reflect.Type {
	return reflect.TypeOf((*externalPluggableDatabasesStackMonitoringState)(nil)).Elem()
}

type externalPluggableDatabasesStackMonitoringArgs struct {
	// (Updatable) Enabling Stack Monitoring on External Pluggable Databases . Requires boolean value "true" or "false".
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	EnableStackMonitoring bool `pulumi:"enableStackMonitoring"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
	ExternalDatabaseConnectorId string `pulumi:"externalDatabaseConnectorId"`
	// The ExternalPluggableDatabaseId [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ExternalPluggableDatabaseId string `pulumi:"externalPluggableDatabaseId"`
}

// The set of arguments for constructing a ExternalPluggableDatabasesStackMonitoring resource.
type ExternalPluggableDatabasesStackMonitoringArgs struct {
	// (Updatable) Enabling Stack Monitoring on External Pluggable Databases . Requires boolean value "true" or "false".
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	EnableStackMonitoring pulumi.BoolInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
	ExternalDatabaseConnectorId pulumi.StringInput
	// The ExternalPluggableDatabaseId [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ExternalPluggableDatabaseId pulumi.StringInput
}

func (ExternalPluggableDatabasesStackMonitoringArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*externalPluggableDatabasesStackMonitoringArgs)(nil)).Elem()
}

type ExternalPluggableDatabasesStackMonitoringInput interface {
	pulumi.Input

	ToExternalPluggableDatabasesStackMonitoringOutput() ExternalPluggableDatabasesStackMonitoringOutput
	ToExternalPluggableDatabasesStackMonitoringOutputWithContext(ctx context.Context) ExternalPluggableDatabasesStackMonitoringOutput
}

func (*ExternalPluggableDatabasesStackMonitoring) ElementType() reflect.Type {
	return reflect.TypeOf((**ExternalPluggableDatabasesStackMonitoring)(nil)).Elem()
}

func (i *ExternalPluggableDatabasesStackMonitoring) ToExternalPluggableDatabasesStackMonitoringOutput() ExternalPluggableDatabasesStackMonitoringOutput {
	return i.ToExternalPluggableDatabasesStackMonitoringOutputWithContext(context.Background())
}

func (i *ExternalPluggableDatabasesStackMonitoring) ToExternalPluggableDatabasesStackMonitoringOutputWithContext(ctx context.Context) ExternalPluggableDatabasesStackMonitoringOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalPluggableDatabasesStackMonitoringOutput)
}

// ExternalPluggableDatabasesStackMonitoringArrayInput is an input type that accepts ExternalPluggableDatabasesStackMonitoringArray and ExternalPluggableDatabasesStackMonitoringArrayOutput values.
// You can construct a concrete instance of `ExternalPluggableDatabasesStackMonitoringArrayInput` via:
//
//	ExternalPluggableDatabasesStackMonitoringArray{ ExternalPluggableDatabasesStackMonitoringArgs{...} }
type ExternalPluggableDatabasesStackMonitoringArrayInput interface {
	pulumi.Input

	ToExternalPluggableDatabasesStackMonitoringArrayOutput() ExternalPluggableDatabasesStackMonitoringArrayOutput
	ToExternalPluggableDatabasesStackMonitoringArrayOutputWithContext(context.Context) ExternalPluggableDatabasesStackMonitoringArrayOutput
}

type ExternalPluggableDatabasesStackMonitoringArray []ExternalPluggableDatabasesStackMonitoringInput

func (ExternalPluggableDatabasesStackMonitoringArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExternalPluggableDatabasesStackMonitoring)(nil)).Elem()
}

func (i ExternalPluggableDatabasesStackMonitoringArray) ToExternalPluggableDatabasesStackMonitoringArrayOutput() ExternalPluggableDatabasesStackMonitoringArrayOutput {
	return i.ToExternalPluggableDatabasesStackMonitoringArrayOutputWithContext(context.Background())
}

func (i ExternalPluggableDatabasesStackMonitoringArray) ToExternalPluggableDatabasesStackMonitoringArrayOutputWithContext(ctx context.Context) ExternalPluggableDatabasesStackMonitoringArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalPluggableDatabasesStackMonitoringArrayOutput)
}

// ExternalPluggableDatabasesStackMonitoringMapInput is an input type that accepts ExternalPluggableDatabasesStackMonitoringMap and ExternalPluggableDatabasesStackMonitoringMapOutput values.
// You can construct a concrete instance of `ExternalPluggableDatabasesStackMonitoringMapInput` via:
//
//	ExternalPluggableDatabasesStackMonitoringMap{ "key": ExternalPluggableDatabasesStackMonitoringArgs{...} }
type ExternalPluggableDatabasesStackMonitoringMapInput interface {
	pulumi.Input

	ToExternalPluggableDatabasesStackMonitoringMapOutput() ExternalPluggableDatabasesStackMonitoringMapOutput
	ToExternalPluggableDatabasesStackMonitoringMapOutputWithContext(context.Context) ExternalPluggableDatabasesStackMonitoringMapOutput
}

type ExternalPluggableDatabasesStackMonitoringMap map[string]ExternalPluggableDatabasesStackMonitoringInput

func (ExternalPluggableDatabasesStackMonitoringMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExternalPluggableDatabasesStackMonitoring)(nil)).Elem()
}

func (i ExternalPluggableDatabasesStackMonitoringMap) ToExternalPluggableDatabasesStackMonitoringMapOutput() ExternalPluggableDatabasesStackMonitoringMapOutput {
	return i.ToExternalPluggableDatabasesStackMonitoringMapOutputWithContext(context.Background())
}

func (i ExternalPluggableDatabasesStackMonitoringMap) ToExternalPluggableDatabasesStackMonitoringMapOutputWithContext(ctx context.Context) ExternalPluggableDatabasesStackMonitoringMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalPluggableDatabasesStackMonitoringMapOutput)
}

type ExternalPluggableDatabasesStackMonitoringOutput struct{ *pulumi.OutputState }

func (ExternalPluggableDatabasesStackMonitoringOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ExternalPluggableDatabasesStackMonitoring)(nil)).Elem()
}

func (o ExternalPluggableDatabasesStackMonitoringOutput) ToExternalPluggableDatabasesStackMonitoringOutput() ExternalPluggableDatabasesStackMonitoringOutput {
	return o
}

func (o ExternalPluggableDatabasesStackMonitoringOutput) ToExternalPluggableDatabasesStackMonitoringOutputWithContext(ctx context.Context) ExternalPluggableDatabasesStackMonitoringOutput {
	return o
}

// (Updatable) Enabling Stack Monitoring on External Pluggable Databases . Requires boolean value "true" or "false".
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ExternalPluggableDatabasesStackMonitoringOutput) EnableStackMonitoring() pulumi.BoolOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabasesStackMonitoring) pulumi.BoolOutput { return v.EnableStackMonitoring }).(pulumi.BoolOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
func (o ExternalPluggableDatabasesStackMonitoringOutput) ExternalDatabaseConnectorId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabasesStackMonitoring) pulumi.StringOutput {
		return v.ExternalDatabaseConnectorId
	}).(pulumi.StringOutput)
}

// The ExternalPluggableDatabaseId [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
func (o ExternalPluggableDatabasesStackMonitoringOutput) ExternalPluggableDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabasesStackMonitoring) pulumi.StringOutput {
		return v.ExternalPluggableDatabaseId
	}).(pulumi.StringOutput)
}

type ExternalPluggableDatabasesStackMonitoringArrayOutput struct{ *pulumi.OutputState }

func (ExternalPluggableDatabasesStackMonitoringArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExternalPluggableDatabasesStackMonitoring)(nil)).Elem()
}

func (o ExternalPluggableDatabasesStackMonitoringArrayOutput) ToExternalPluggableDatabasesStackMonitoringArrayOutput() ExternalPluggableDatabasesStackMonitoringArrayOutput {
	return o
}

func (o ExternalPluggableDatabasesStackMonitoringArrayOutput) ToExternalPluggableDatabasesStackMonitoringArrayOutputWithContext(ctx context.Context) ExternalPluggableDatabasesStackMonitoringArrayOutput {
	return o
}

func (o ExternalPluggableDatabasesStackMonitoringArrayOutput) Index(i pulumi.IntInput) ExternalPluggableDatabasesStackMonitoringOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ExternalPluggableDatabasesStackMonitoring {
		return vs[0].([]*ExternalPluggableDatabasesStackMonitoring)[vs[1].(int)]
	}).(ExternalPluggableDatabasesStackMonitoringOutput)
}

type ExternalPluggableDatabasesStackMonitoringMapOutput struct{ *pulumi.OutputState }

func (ExternalPluggableDatabasesStackMonitoringMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExternalPluggableDatabasesStackMonitoring)(nil)).Elem()
}

func (o ExternalPluggableDatabasesStackMonitoringMapOutput) ToExternalPluggableDatabasesStackMonitoringMapOutput() ExternalPluggableDatabasesStackMonitoringMapOutput {
	return o
}

func (o ExternalPluggableDatabasesStackMonitoringMapOutput) ToExternalPluggableDatabasesStackMonitoringMapOutputWithContext(ctx context.Context) ExternalPluggableDatabasesStackMonitoringMapOutput {
	return o
}

func (o ExternalPluggableDatabasesStackMonitoringMapOutput) MapIndex(k pulumi.StringInput) ExternalPluggableDatabasesStackMonitoringOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ExternalPluggableDatabasesStackMonitoring {
		return vs[0].(map[string]*ExternalPluggableDatabasesStackMonitoring)[vs[1].(string)]
	}).(ExternalPluggableDatabasesStackMonitoringOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalPluggableDatabasesStackMonitoringInput)(nil)).Elem(), &ExternalPluggableDatabasesStackMonitoring{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalPluggableDatabasesStackMonitoringArrayInput)(nil)).Elem(), ExternalPluggableDatabasesStackMonitoringArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalPluggableDatabasesStackMonitoringMapInput)(nil)).Elem(), ExternalPluggableDatabasesStackMonitoringMap{})
	pulumi.RegisterOutputType(ExternalPluggableDatabasesStackMonitoringOutput{})
	pulumi.RegisterOutputType(ExternalPluggableDatabasesStackMonitoringArrayOutput{})
	pulumi.RegisterOutputType(ExternalPluggableDatabasesStackMonitoringMapOutput{})
}
