// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Externalnoncontainerdatabases Stack Monitoring resource in Oracle Cloud Infrastructure Database service.
//
// Enable Stack Monitoring for the external non-container database.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Database.NewExternalNonContainerDatabasesStackMonitoring(ctx, "testExternalnoncontainerdatabasesStackMonitoring", &Database.ExternalNonContainerDatabasesStackMonitoringArgs{
//				ExternalDatabaseConnectorId:    pulumi.Any(oci_database_external_database_connector.Test_external_database_connector.Id),
//				ExternalNonContainerDatabaseId: pulumi.Any(oci_database_external_non_container_database.Test_external_non_container_database.Id),
//				EnableStackMonitoring:          pulumi.Bool(true),
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
type ExternalNonContainerDatabasesStackMonitoring struct {
	pulumi.CustomResourceState

	// (Updatable) Enabling Stack Monitoring on External Non Container Databases . Requires boolean value "true" or "false".
	EnableStackMonitoring pulumi.BoolOutput `pulumi:"enableStackMonitoring"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
	ExternalDatabaseConnectorId pulumi.StringOutput `pulumi:"externalDatabaseConnectorId"`
	// The external non-container database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ExternalNonContainerDatabaseId pulumi.StringOutput `pulumi:"externalNonContainerDatabaseId"`
}

// NewExternalNonContainerDatabasesStackMonitoring registers a new resource with the given unique name, arguments, and options.
func NewExternalNonContainerDatabasesStackMonitoring(ctx *pulumi.Context,
	name string, args *ExternalNonContainerDatabasesStackMonitoringArgs, opts ...pulumi.ResourceOption) (*ExternalNonContainerDatabasesStackMonitoring, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.EnableStackMonitoring == nil {
		return nil, errors.New("invalid value for required argument 'EnableStackMonitoring'")
	}
	if args.ExternalDatabaseConnectorId == nil {
		return nil, errors.New("invalid value for required argument 'ExternalDatabaseConnectorId'")
	}
	if args.ExternalNonContainerDatabaseId == nil {
		return nil, errors.New("invalid value for required argument 'ExternalNonContainerDatabaseId'")
	}
	var resource ExternalNonContainerDatabasesStackMonitoring
	err := ctx.RegisterResource("oci:Database/externalNonContainerDatabasesStackMonitoring:ExternalNonContainerDatabasesStackMonitoring", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetExternalNonContainerDatabasesStackMonitoring gets an existing ExternalNonContainerDatabasesStackMonitoring resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetExternalNonContainerDatabasesStackMonitoring(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ExternalNonContainerDatabasesStackMonitoringState, opts ...pulumi.ResourceOption) (*ExternalNonContainerDatabasesStackMonitoring, error) {
	var resource ExternalNonContainerDatabasesStackMonitoring
	err := ctx.ReadResource("oci:Database/externalNonContainerDatabasesStackMonitoring:ExternalNonContainerDatabasesStackMonitoring", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ExternalNonContainerDatabasesStackMonitoring resources.
type externalNonContainerDatabasesStackMonitoringState struct {
	// (Updatable) Enabling Stack Monitoring on External Non Container Databases . Requires boolean value "true" or "false".
	EnableStackMonitoring *bool `pulumi:"enableStackMonitoring"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
	ExternalDatabaseConnectorId *string `pulumi:"externalDatabaseConnectorId"`
	// The external non-container database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ExternalNonContainerDatabaseId *string `pulumi:"externalNonContainerDatabaseId"`
}

type ExternalNonContainerDatabasesStackMonitoringState struct {
	// (Updatable) Enabling Stack Monitoring on External Non Container Databases . Requires boolean value "true" or "false".
	EnableStackMonitoring pulumi.BoolPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
	ExternalDatabaseConnectorId pulumi.StringPtrInput
	// The external non-container database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ExternalNonContainerDatabaseId pulumi.StringPtrInput
}

func (ExternalNonContainerDatabasesStackMonitoringState) ElementType() reflect.Type {
	return reflect.TypeOf((*externalNonContainerDatabasesStackMonitoringState)(nil)).Elem()
}

type externalNonContainerDatabasesStackMonitoringArgs struct {
	// (Updatable) Enabling Stack Monitoring on External Non Container Databases . Requires boolean value "true" or "false".
	EnableStackMonitoring bool `pulumi:"enableStackMonitoring"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
	ExternalDatabaseConnectorId string `pulumi:"externalDatabaseConnectorId"`
	// The external non-container database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ExternalNonContainerDatabaseId string `pulumi:"externalNonContainerDatabaseId"`
}

// The set of arguments for constructing a ExternalNonContainerDatabasesStackMonitoring resource.
type ExternalNonContainerDatabasesStackMonitoringArgs struct {
	// (Updatable) Enabling Stack Monitoring on External Non Container Databases . Requires boolean value "true" or "false".
	EnableStackMonitoring pulumi.BoolInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
	ExternalDatabaseConnectorId pulumi.StringInput
	// The external non-container database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	ExternalNonContainerDatabaseId pulumi.StringInput
}

func (ExternalNonContainerDatabasesStackMonitoringArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*externalNonContainerDatabasesStackMonitoringArgs)(nil)).Elem()
}

type ExternalNonContainerDatabasesStackMonitoringInput interface {
	pulumi.Input

	ToExternalNonContainerDatabasesStackMonitoringOutput() ExternalNonContainerDatabasesStackMonitoringOutput
	ToExternalNonContainerDatabasesStackMonitoringOutputWithContext(ctx context.Context) ExternalNonContainerDatabasesStackMonitoringOutput
}

func (*ExternalNonContainerDatabasesStackMonitoring) ElementType() reflect.Type {
	return reflect.TypeOf((**ExternalNonContainerDatabasesStackMonitoring)(nil)).Elem()
}

func (i *ExternalNonContainerDatabasesStackMonitoring) ToExternalNonContainerDatabasesStackMonitoringOutput() ExternalNonContainerDatabasesStackMonitoringOutput {
	return i.ToExternalNonContainerDatabasesStackMonitoringOutputWithContext(context.Background())
}

func (i *ExternalNonContainerDatabasesStackMonitoring) ToExternalNonContainerDatabasesStackMonitoringOutputWithContext(ctx context.Context) ExternalNonContainerDatabasesStackMonitoringOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalNonContainerDatabasesStackMonitoringOutput)
}

// ExternalNonContainerDatabasesStackMonitoringArrayInput is an input type that accepts ExternalNonContainerDatabasesStackMonitoringArray and ExternalNonContainerDatabasesStackMonitoringArrayOutput values.
// You can construct a concrete instance of `ExternalNonContainerDatabasesStackMonitoringArrayInput` via:
//
//	ExternalNonContainerDatabasesStackMonitoringArray{ ExternalNonContainerDatabasesStackMonitoringArgs{...} }
type ExternalNonContainerDatabasesStackMonitoringArrayInput interface {
	pulumi.Input

	ToExternalNonContainerDatabasesStackMonitoringArrayOutput() ExternalNonContainerDatabasesStackMonitoringArrayOutput
	ToExternalNonContainerDatabasesStackMonitoringArrayOutputWithContext(context.Context) ExternalNonContainerDatabasesStackMonitoringArrayOutput
}

type ExternalNonContainerDatabasesStackMonitoringArray []ExternalNonContainerDatabasesStackMonitoringInput

func (ExternalNonContainerDatabasesStackMonitoringArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExternalNonContainerDatabasesStackMonitoring)(nil)).Elem()
}

func (i ExternalNonContainerDatabasesStackMonitoringArray) ToExternalNonContainerDatabasesStackMonitoringArrayOutput() ExternalNonContainerDatabasesStackMonitoringArrayOutput {
	return i.ToExternalNonContainerDatabasesStackMonitoringArrayOutputWithContext(context.Background())
}

func (i ExternalNonContainerDatabasesStackMonitoringArray) ToExternalNonContainerDatabasesStackMonitoringArrayOutputWithContext(ctx context.Context) ExternalNonContainerDatabasesStackMonitoringArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalNonContainerDatabasesStackMonitoringArrayOutput)
}

// ExternalNonContainerDatabasesStackMonitoringMapInput is an input type that accepts ExternalNonContainerDatabasesStackMonitoringMap and ExternalNonContainerDatabasesStackMonitoringMapOutput values.
// You can construct a concrete instance of `ExternalNonContainerDatabasesStackMonitoringMapInput` via:
//
//	ExternalNonContainerDatabasesStackMonitoringMap{ "key": ExternalNonContainerDatabasesStackMonitoringArgs{...} }
type ExternalNonContainerDatabasesStackMonitoringMapInput interface {
	pulumi.Input

	ToExternalNonContainerDatabasesStackMonitoringMapOutput() ExternalNonContainerDatabasesStackMonitoringMapOutput
	ToExternalNonContainerDatabasesStackMonitoringMapOutputWithContext(context.Context) ExternalNonContainerDatabasesStackMonitoringMapOutput
}

type ExternalNonContainerDatabasesStackMonitoringMap map[string]ExternalNonContainerDatabasesStackMonitoringInput

func (ExternalNonContainerDatabasesStackMonitoringMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExternalNonContainerDatabasesStackMonitoring)(nil)).Elem()
}

func (i ExternalNonContainerDatabasesStackMonitoringMap) ToExternalNonContainerDatabasesStackMonitoringMapOutput() ExternalNonContainerDatabasesStackMonitoringMapOutput {
	return i.ToExternalNonContainerDatabasesStackMonitoringMapOutputWithContext(context.Background())
}

func (i ExternalNonContainerDatabasesStackMonitoringMap) ToExternalNonContainerDatabasesStackMonitoringMapOutputWithContext(ctx context.Context) ExternalNonContainerDatabasesStackMonitoringMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalNonContainerDatabasesStackMonitoringMapOutput)
}

type ExternalNonContainerDatabasesStackMonitoringOutput struct{ *pulumi.OutputState }

func (ExternalNonContainerDatabasesStackMonitoringOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ExternalNonContainerDatabasesStackMonitoring)(nil)).Elem()
}

func (o ExternalNonContainerDatabasesStackMonitoringOutput) ToExternalNonContainerDatabasesStackMonitoringOutput() ExternalNonContainerDatabasesStackMonitoringOutput {
	return o
}

func (o ExternalNonContainerDatabasesStackMonitoringOutput) ToExternalNonContainerDatabasesStackMonitoringOutputWithContext(ctx context.Context) ExternalNonContainerDatabasesStackMonitoringOutput {
	return o
}

// (Updatable) Enabling Stack Monitoring on External Non Container Databases . Requires boolean value "true" or "false".
func (o ExternalNonContainerDatabasesStackMonitoringOutput) EnableStackMonitoring() pulumi.BoolOutput {
	return o.ApplyT(func(v *ExternalNonContainerDatabasesStackMonitoring) pulumi.BoolOutput {
		return v.EnableStackMonitoring
	}).(pulumi.BoolOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
func (o ExternalNonContainerDatabasesStackMonitoringOutput) ExternalDatabaseConnectorId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalNonContainerDatabasesStackMonitoring) pulumi.StringOutput {
		return v.ExternalDatabaseConnectorId
	}).(pulumi.StringOutput)
}

// The external non-container database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
func (o ExternalNonContainerDatabasesStackMonitoringOutput) ExternalNonContainerDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalNonContainerDatabasesStackMonitoring) pulumi.StringOutput {
		return v.ExternalNonContainerDatabaseId
	}).(pulumi.StringOutput)
}

type ExternalNonContainerDatabasesStackMonitoringArrayOutput struct{ *pulumi.OutputState }

func (ExternalNonContainerDatabasesStackMonitoringArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExternalNonContainerDatabasesStackMonitoring)(nil)).Elem()
}

func (o ExternalNonContainerDatabasesStackMonitoringArrayOutput) ToExternalNonContainerDatabasesStackMonitoringArrayOutput() ExternalNonContainerDatabasesStackMonitoringArrayOutput {
	return o
}

func (o ExternalNonContainerDatabasesStackMonitoringArrayOutput) ToExternalNonContainerDatabasesStackMonitoringArrayOutputWithContext(ctx context.Context) ExternalNonContainerDatabasesStackMonitoringArrayOutput {
	return o
}

func (o ExternalNonContainerDatabasesStackMonitoringArrayOutput) Index(i pulumi.IntInput) ExternalNonContainerDatabasesStackMonitoringOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ExternalNonContainerDatabasesStackMonitoring {
		return vs[0].([]*ExternalNonContainerDatabasesStackMonitoring)[vs[1].(int)]
	}).(ExternalNonContainerDatabasesStackMonitoringOutput)
}

type ExternalNonContainerDatabasesStackMonitoringMapOutput struct{ *pulumi.OutputState }

func (ExternalNonContainerDatabasesStackMonitoringMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExternalNonContainerDatabasesStackMonitoring)(nil)).Elem()
}

func (o ExternalNonContainerDatabasesStackMonitoringMapOutput) ToExternalNonContainerDatabasesStackMonitoringMapOutput() ExternalNonContainerDatabasesStackMonitoringMapOutput {
	return o
}

func (o ExternalNonContainerDatabasesStackMonitoringMapOutput) ToExternalNonContainerDatabasesStackMonitoringMapOutputWithContext(ctx context.Context) ExternalNonContainerDatabasesStackMonitoringMapOutput {
	return o
}

func (o ExternalNonContainerDatabasesStackMonitoringMapOutput) MapIndex(k pulumi.StringInput) ExternalNonContainerDatabasesStackMonitoringOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ExternalNonContainerDatabasesStackMonitoring {
		return vs[0].(map[string]*ExternalNonContainerDatabasesStackMonitoring)[vs[1].(string)]
	}).(ExternalNonContainerDatabasesStackMonitoringOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalNonContainerDatabasesStackMonitoringInput)(nil)).Elem(), &ExternalNonContainerDatabasesStackMonitoring{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalNonContainerDatabasesStackMonitoringArrayInput)(nil)).Elem(), ExternalNonContainerDatabasesStackMonitoringArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalNonContainerDatabasesStackMonitoringMapInput)(nil)).Elem(), ExternalNonContainerDatabasesStackMonitoringMap{})
	pulumi.RegisterOutputType(ExternalNonContainerDatabasesStackMonitoringOutput{})
	pulumi.RegisterOutputType(ExternalNonContainerDatabasesStackMonitoringArrayOutput{})
	pulumi.RegisterOutputType(ExternalNonContainerDatabasesStackMonitoringMapOutput{})
}