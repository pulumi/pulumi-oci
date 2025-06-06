// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Calculate Audit Volume Available resource in Oracle Cloud Infrastructure Data Safe service.
//
// Calculates the volume of audit events available on the target database to be collected. Measurable up to the defined retention period of the audit target resource.
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
//			_, err := datasafe.NewCalculateAuditVolumeAvailable(ctx, "test_calculate_audit_volume_available", &datasafe.CalculateAuditVolumeAvailableArgs{
//				AuditProfileId:           pulumi.Any(testAuditProfile.Id),
//				AuditCollectionStartTime: pulumi.Any(calculateAuditVolumeAvailableAuditCollectionStartTime),
//				DatabaseUniqueName:       pulumi.Any(calculateAuditVolumeAvailableDatabaseUniqueName),
//				TrailLocations:           pulumi.Any(calculateAuditVolumeAvailableTrailLocations),
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
// CalculateAuditVolumeAvailable can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DataSafe/calculateAuditVolumeAvailable:CalculateAuditVolumeAvailable test_calculate_audit_volume_available "id"
// ```
type CalculateAuditVolumeAvailable struct {
	pulumi.CustomResourceState

	// The date from which the audit trail must start collecting data in UTC, in the format defined by RFC3339. If not specified, this will default to the date based on the retention period.
	AuditCollectionStartTime pulumi.StringOutput `pulumi:"auditCollectionStartTime"`
	// The OCID of the audit.
	AuditProfileId pulumi.StringOutput `pulumi:"auditProfileId"`
	// List of available audit volumes.
	AvailableAuditVolumes CalculateAuditVolumeAvailableAvailableAuditVolumeArrayOutput `pulumi:"availableAuditVolumes"`
	// Unique name of the database associated to the peer target database.
	DatabaseUniqueName pulumi.StringOutput `pulumi:"databaseUniqueName"`
	// The trail locations for which the audit data volume has to be calculated.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TrailLocations pulumi.StringArrayOutput `pulumi:"trailLocations"`
}

// NewCalculateAuditVolumeAvailable registers a new resource with the given unique name, arguments, and options.
func NewCalculateAuditVolumeAvailable(ctx *pulumi.Context,
	name string, args *CalculateAuditVolumeAvailableArgs, opts ...pulumi.ResourceOption) (*CalculateAuditVolumeAvailable, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AuditProfileId == nil {
		return nil, errors.New("invalid value for required argument 'AuditProfileId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource CalculateAuditVolumeAvailable
	err := ctx.RegisterResource("oci:DataSafe/calculateAuditVolumeAvailable:CalculateAuditVolumeAvailable", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCalculateAuditVolumeAvailable gets an existing CalculateAuditVolumeAvailable resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCalculateAuditVolumeAvailable(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CalculateAuditVolumeAvailableState, opts ...pulumi.ResourceOption) (*CalculateAuditVolumeAvailable, error) {
	var resource CalculateAuditVolumeAvailable
	err := ctx.ReadResource("oci:DataSafe/calculateAuditVolumeAvailable:CalculateAuditVolumeAvailable", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CalculateAuditVolumeAvailable resources.
type calculateAuditVolumeAvailableState struct {
	// The date from which the audit trail must start collecting data in UTC, in the format defined by RFC3339. If not specified, this will default to the date based on the retention period.
	AuditCollectionStartTime *string `pulumi:"auditCollectionStartTime"`
	// The OCID of the audit.
	AuditProfileId *string `pulumi:"auditProfileId"`
	// List of available audit volumes.
	AvailableAuditVolumes []CalculateAuditVolumeAvailableAvailableAuditVolume `pulumi:"availableAuditVolumes"`
	// Unique name of the database associated to the peer target database.
	DatabaseUniqueName *string `pulumi:"databaseUniqueName"`
	// The trail locations for which the audit data volume has to be calculated.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TrailLocations []string `pulumi:"trailLocations"`
}

type CalculateAuditVolumeAvailableState struct {
	// The date from which the audit trail must start collecting data in UTC, in the format defined by RFC3339. If not specified, this will default to the date based on the retention period.
	AuditCollectionStartTime pulumi.StringPtrInput
	// The OCID of the audit.
	AuditProfileId pulumi.StringPtrInput
	// List of available audit volumes.
	AvailableAuditVolumes CalculateAuditVolumeAvailableAvailableAuditVolumeArrayInput
	// Unique name of the database associated to the peer target database.
	DatabaseUniqueName pulumi.StringPtrInput
	// The trail locations for which the audit data volume has to be calculated.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TrailLocations pulumi.StringArrayInput
}

func (CalculateAuditVolumeAvailableState) ElementType() reflect.Type {
	return reflect.TypeOf((*calculateAuditVolumeAvailableState)(nil)).Elem()
}

type calculateAuditVolumeAvailableArgs struct {
	// The date from which the audit trail must start collecting data in UTC, in the format defined by RFC3339. If not specified, this will default to the date based on the retention period.
	AuditCollectionStartTime *string `pulumi:"auditCollectionStartTime"`
	// The OCID of the audit.
	AuditProfileId string `pulumi:"auditProfileId"`
	// Unique name of the database associated to the peer target database.
	DatabaseUniqueName *string `pulumi:"databaseUniqueName"`
	// The trail locations for which the audit data volume has to be calculated.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TrailLocations []string `pulumi:"trailLocations"`
}

// The set of arguments for constructing a CalculateAuditVolumeAvailable resource.
type CalculateAuditVolumeAvailableArgs struct {
	// The date from which the audit trail must start collecting data in UTC, in the format defined by RFC3339. If not specified, this will default to the date based on the retention period.
	AuditCollectionStartTime pulumi.StringPtrInput
	// The OCID of the audit.
	AuditProfileId pulumi.StringInput
	// Unique name of the database associated to the peer target database.
	DatabaseUniqueName pulumi.StringPtrInput
	// The trail locations for which the audit data volume has to be calculated.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TrailLocations pulumi.StringArrayInput
}

func (CalculateAuditVolumeAvailableArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*calculateAuditVolumeAvailableArgs)(nil)).Elem()
}

type CalculateAuditVolumeAvailableInput interface {
	pulumi.Input

	ToCalculateAuditVolumeAvailableOutput() CalculateAuditVolumeAvailableOutput
	ToCalculateAuditVolumeAvailableOutputWithContext(ctx context.Context) CalculateAuditVolumeAvailableOutput
}

func (*CalculateAuditVolumeAvailable) ElementType() reflect.Type {
	return reflect.TypeOf((**CalculateAuditVolumeAvailable)(nil)).Elem()
}

func (i *CalculateAuditVolumeAvailable) ToCalculateAuditVolumeAvailableOutput() CalculateAuditVolumeAvailableOutput {
	return i.ToCalculateAuditVolumeAvailableOutputWithContext(context.Background())
}

func (i *CalculateAuditVolumeAvailable) ToCalculateAuditVolumeAvailableOutputWithContext(ctx context.Context) CalculateAuditVolumeAvailableOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CalculateAuditVolumeAvailableOutput)
}

// CalculateAuditVolumeAvailableArrayInput is an input type that accepts CalculateAuditVolumeAvailableArray and CalculateAuditVolumeAvailableArrayOutput values.
// You can construct a concrete instance of `CalculateAuditVolumeAvailableArrayInput` via:
//
//	CalculateAuditVolumeAvailableArray{ CalculateAuditVolumeAvailableArgs{...} }
type CalculateAuditVolumeAvailableArrayInput interface {
	pulumi.Input

	ToCalculateAuditVolumeAvailableArrayOutput() CalculateAuditVolumeAvailableArrayOutput
	ToCalculateAuditVolumeAvailableArrayOutputWithContext(context.Context) CalculateAuditVolumeAvailableArrayOutput
}

type CalculateAuditVolumeAvailableArray []CalculateAuditVolumeAvailableInput

func (CalculateAuditVolumeAvailableArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CalculateAuditVolumeAvailable)(nil)).Elem()
}

func (i CalculateAuditVolumeAvailableArray) ToCalculateAuditVolumeAvailableArrayOutput() CalculateAuditVolumeAvailableArrayOutput {
	return i.ToCalculateAuditVolumeAvailableArrayOutputWithContext(context.Background())
}

func (i CalculateAuditVolumeAvailableArray) ToCalculateAuditVolumeAvailableArrayOutputWithContext(ctx context.Context) CalculateAuditVolumeAvailableArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CalculateAuditVolumeAvailableArrayOutput)
}

// CalculateAuditVolumeAvailableMapInput is an input type that accepts CalculateAuditVolumeAvailableMap and CalculateAuditVolumeAvailableMapOutput values.
// You can construct a concrete instance of `CalculateAuditVolumeAvailableMapInput` via:
//
//	CalculateAuditVolumeAvailableMap{ "key": CalculateAuditVolumeAvailableArgs{...} }
type CalculateAuditVolumeAvailableMapInput interface {
	pulumi.Input

	ToCalculateAuditVolumeAvailableMapOutput() CalculateAuditVolumeAvailableMapOutput
	ToCalculateAuditVolumeAvailableMapOutputWithContext(context.Context) CalculateAuditVolumeAvailableMapOutput
}

type CalculateAuditVolumeAvailableMap map[string]CalculateAuditVolumeAvailableInput

func (CalculateAuditVolumeAvailableMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CalculateAuditVolumeAvailable)(nil)).Elem()
}

func (i CalculateAuditVolumeAvailableMap) ToCalculateAuditVolumeAvailableMapOutput() CalculateAuditVolumeAvailableMapOutput {
	return i.ToCalculateAuditVolumeAvailableMapOutputWithContext(context.Background())
}

func (i CalculateAuditVolumeAvailableMap) ToCalculateAuditVolumeAvailableMapOutputWithContext(ctx context.Context) CalculateAuditVolumeAvailableMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CalculateAuditVolumeAvailableMapOutput)
}

type CalculateAuditVolumeAvailableOutput struct{ *pulumi.OutputState }

func (CalculateAuditVolumeAvailableOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CalculateAuditVolumeAvailable)(nil)).Elem()
}

func (o CalculateAuditVolumeAvailableOutput) ToCalculateAuditVolumeAvailableOutput() CalculateAuditVolumeAvailableOutput {
	return o
}

func (o CalculateAuditVolumeAvailableOutput) ToCalculateAuditVolumeAvailableOutputWithContext(ctx context.Context) CalculateAuditVolumeAvailableOutput {
	return o
}

// The date from which the audit trail must start collecting data in UTC, in the format defined by RFC3339. If not specified, this will default to the date based on the retention period.
func (o CalculateAuditVolumeAvailableOutput) AuditCollectionStartTime() pulumi.StringOutput {
	return o.ApplyT(func(v *CalculateAuditVolumeAvailable) pulumi.StringOutput { return v.AuditCollectionStartTime }).(pulumi.StringOutput)
}

// The OCID of the audit.
func (o CalculateAuditVolumeAvailableOutput) AuditProfileId() pulumi.StringOutput {
	return o.ApplyT(func(v *CalculateAuditVolumeAvailable) pulumi.StringOutput { return v.AuditProfileId }).(pulumi.StringOutput)
}

// List of available audit volumes.
func (o CalculateAuditVolumeAvailableOutput) AvailableAuditVolumes() CalculateAuditVolumeAvailableAvailableAuditVolumeArrayOutput {
	return o.ApplyT(func(v *CalculateAuditVolumeAvailable) CalculateAuditVolumeAvailableAvailableAuditVolumeArrayOutput {
		return v.AvailableAuditVolumes
	}).(CalculateAuditVolumeAvailableAvailableAuditVolumeArrayOutput)
}

// Unique name of the database associated to the peer target database.
func (o CalculateAuditVolumeAvailableOutput) DatabaseUniqueName() pulumi.StringOutput {
	return o.ApplyT(func(v *CalculateAuditVolumeAvailable) pulumi.StringOutput { return v.DatabaseUniqueName }).(pulumi.StringOutput)
}

// The trail locations for which the audit data volume has to be calculated.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o CalculateAuditVolumeAvailableOutput) TrailLocations() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *CalculateAuditVolumeAvailable) pulumi.StringArrayOutput { return v.TrailLocations }).(pulumi.StringArrayOutput)
}

type CalculateAuditVolumeAvailableArrayOutput struct{ *pulumi.OutputState }

func (CalculateAuditVolumeAvailableArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CalculateAuditVolumeAvailable)(nil)).Elem()
}

func (o CalculateAuditVolumeAvailableArrayOutput) ToCalculateAuditVolumeAvailableArrayOutput() CalculateAuditVolumeAvailableArrayOutput {
	return o
}

func (o CalculateAuditVolumeAvailableArrayOutput) ToCalculateAuditVolumeAvailableArrayOutputWithContext(ctx context.Context) CalculateAuditVolumeAvailableArrayOutput {
	return o
}

func (o CalculateAuditVolumeAvailableArrayOutput) Index(i pulumi.IntInput) CalculateAuditVolumeAvailableOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *CalculateAuditVolumeAvailable {
		return vs[0].([]*CalculateAuditVolumeAvailable)[vs[1].(int)]
	}).(CalculateAuditVolumeAvailableOutput)
}

type CalculateAuditVolumeAvailableMapOutput struct{ *pulumi.OutputState }

func (CalculateAuditVolumeAvailableMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CalculateAuditVolumeAvailable)(nil)).Elem()
}

func (o CalculateAuditVolumeAvailableMapOutput) ToCalculateAuditVolumeAvailableMapOutput() CalculateAuditVolumeAvailableMapOutput {
	return o
}

func (o CalculateAuditVolumeAvailableMapOutput) ToCalculateAuditVolumeAvailableMapOutputWithContext(ctx context.Context) CalculateAuditVolumeAvailableMapOutput {
	return o
}

func (o CalculateAuditVolumeAvailableMapOutput) MapIndex(k pulumi.StringInput) CalculateAuditVolumeAvailableOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *CalculateAuditVolumeAvailable {
		return vs[0].(map[string]*CalculateAuditVolumeAvailable)[vs[1].(string)]
	}).(CalculateAuditVolumeAvailableOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*CalculateAuditVolumeAvailableInput)(nil)).Elem(), &CalculateAuditVolumeAvailable{})
	pulumi.RegisterInputType(reflect.TypeOf((*CalculateAuditVolumeAvailableArrayInput)(nil)).Elem(), CalculateAuditVolumeAvailableArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*CalculateAuditVolumeAvailableMapInput)(nil)).Elem(), CalculateAuditVolumeAvailableMap{})
	pulumi.RegisterOutputType(CalculateAuditVolumeAvailableOutput{})
	pulumi.RegisterOutputType(CalculateAuditVolumeAvailableArrayOutput{})
	pulumi.RegisterOutputType(CalculateAuditVolumeAvailableMapOutput{})
}
