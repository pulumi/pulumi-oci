// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package filestorage

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Replication resource in Oracle Cloud Infrastructure File Storage service.
//
// Creates a new replication in the specified compartment.
// Replications are the primary resource that governs the policy of cross-region replication between source
// and target file systems. Replications are associated with a secondary resource called a [`ReplicationTarget`](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ReplicationTarget)
// located in another availability domain.
// The associated replication target resource is automatically created along with the replication resource.
// The replication retrieves the delta of data between two snapshots of a source file system
// and sends it to the associated `ReplicationTarget`, which retrieves the delta and applies it to the target
// file system.
// Only unexported file systems can be used as target file systems.
// For more information, see [Using Replication](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/FSreplication.htm).
//
// For information about access control and compartments, see
// [Overview of the IAM
// Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
//
// For information about availability domains, see [Regions and
// Availability Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm).
// To get a list of availability domains, use the
// `ListAvailabilityDomains` operation in the Identity and Access
// Management Service API.
//
// All Oracle Cloud Infrastructure Services resources, including
// replications, get an Oracle-assigned, unique ID called an
// Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
// When you create a resource, you can find its OCID in the response.
// You can also retrieve a resource's OCID by using a List API operation on that resource
// type, or by viewing the resource in the Console.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/filestorage"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := filestorage.NewReplication(ctx, "test_replication", &filestorage.ReplicationArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				SourceId:      pulumi.Any(testSource.Id),
//				TargetId:      pulumi.Any(testTarget.Id),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				DisplayName: pulumi.Any(replicationDisplayName),
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
//				},
//				Locks: filestorage.ReplicationLockArray{
//					&filestorage.ReplicationLockArgs{
//						Type:              pulumi.Any(replicationLocksType),
//						Message:           pulumi.Any(replicationLocksMessage),
//						RelatedResourceId: pulumi.Any(testResource.Id),
//						TimeCreated:       pulumi.Any(replicationLocksTimeCreated),
//					},
//				},
//				ReplicationInterval: pulumi.Any(replicationReplicationInterval),
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
// Replications can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:FileStorage/replication:Replication test_replication "id"
// ```
type Replication struct {
	pulumi.CustomResourceState

	// The availability domain the replication is in. The replication must be in the same availability domain as the source file system. Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringOutput `pulumi:"availabilityDomain"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the replication.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// Percentage progress of the current replication cycle.
	DeltaProgress pulumi.StringOutput `pulumi:"deltaProgress"`
	// The current state of the snapshot during replication operations.
	DeltaStatus pulumi.StringOutput `pulumi:"deltaStatus"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information. An associated replication target will also created with the same `displayName`. Example: `My replication`
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags   pulumi.StringMapOutput `pulumi:"freeformTags"`
	IsLockOverride pulumi.BoolOutput      `pulumi:"isLockOverride"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last snapshot that has been replicated completely. Empty if the copy of the initial snapshot is not complete.
	LastSnapshotId pulumi.StringOutput `pulumi:"lastSnapshotId"`
	// Additional information about the current 'lifecycleState'.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// Locks associated with this resource.
	Locks ReplicationLockArrayOutput `pulumi:"locks"`
	// The [`snapshotTime`](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Snapshot/snapshotTime) of the most recent recoverable replication snapshot in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format. Example: `2021-04-04T20:01:29.100Z`
	RecoveryPointTime pulumi.StringOutput `pulumi:"recoveryPointTime"`
	// (Updatable) Duration in minutes between replication snapshots.
	ReplicationInterval pulumi.StringOutput `pulumi:"replicationInterval"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [`ReplicationTarget`](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ReplicationTarget).
	ReplicationTargetId pulumi.StringOutput `pulumi:"replicationTargetId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source file system.
	SourceId pulumi.StringOutput `pulumi:"sourceId"`
	// The current state of this replication. This resource can be in a `FAILED` state if replication target is deleted instead of the replication resource.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. System tags are applied to resources by internal Oracle Cloud Infrastructure services.
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target file system.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TargetId pulumi.StringOutput `pulumi:"targetId"`
	// The date and time the replication was created in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2021-01-04T20:01:29.100Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewReplication registers a new resource with the given unique name, arguments, and options.
func NewReplication(ctx *pulumi.Context,
	name string, args *ReplicationArgs, opts ...pulumi.ResourceOption) (*Replication, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.SourceId == nil {
		return nil, errors.New("invalid value for required argument 'SourceId'")
	}
	if args.TargetId == nil {
		return nil, errors.New("invalid value for required argument 'TargetId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource Replication
	err := ctx.RegisterResource("oci:FileStorage/replication:Replication", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetReplication gets an existing Replication resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetReplication(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ReplicationState, opts ...pulumi.ResourceOption) (*Replication, error) {
	var resource Replication
	err := ctx.ReadResource("oci:FileStorage/replication:Replication", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Replication resources.
type replicationState struct {
	// The availability domain the replication is in. The replication must be in the same availability domain as the source file system. Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the replication.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Percentage progress of the current replication cycle.
	DeltaProgress *string `pulumi:"deltaProgress"`
	// The current state of the snapshot during replication operations.
	DeltaStatus *string `pulumi:"deltaStatus"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information. An associated replication target will also created with the same `displayName`. Example: `My replication`
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags   map[string]string `pulumi:"freeformTags"`
	IsLockOverride *bool             `pulumi:"isLockOverride"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last snapshot that has been replicated completely. Empty if the copy of the initial snapshot is not complete.
	LastSnapshotId *string `pulumi:"lastSnapshotId"`
	// Additional information about the current 'lifecycleState'.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// Locks associated with this resource.
	Locks []ReplicationLock `pulumi:"locks"`
	// The [`snapshotTime`](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Snapshot/snapshotTime) of the most recent recoverable replication snapshot in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format. Example: `2021-04-04T20:01:29.100Z`
	RecoveryPointTime *string `pulumi:"recoveryPointTime"`
	// (Updatable) Duration in minutes between replication snapshots.
	ReplicationInterval *string `pulumi:"replicationInterval"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [`ReplicationTarget`](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ReplicationTarget).
	ReplicationTargetId *string `pulumi:"replicationTargetId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source file system.
	SourceId *string `pulumi:"sourceId"`
	// The current state of this replication. This resource can be in a `FAILED` state if replication target is deleted instead of the replication resource.
	State *string `pulumi:"state"`
	// System tags for this resource. System tags are applied to resources by internal Oracle Cloud Infrastructure services.
	SystemTags map[string]string `pulumi:"systemTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target file system.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TargetId *string `pulumi:"targetId"`
	// The date and time the replication was created in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2021-01-04T20:01:29.100Z`
	TimeCreated *string `pulumi:"timeCreated"`
}

type ReplicationState struct {
	// The availability domain the replication is in. The replication must be in the same availability domain as the source file system. Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the replication.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// Percentage progress of the current replication cycle.
	DeltaProgress pulumi.StringPtrInput
	// The current state of the snapshot during replication operations.
	DeltaStatus pulumi.StringPtrInput
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information. An associated replication target will also created with the same `displayName`. Example: `My replication`
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags   pulumi.StringMapInput
	IsLockOverride pulumi.BoolPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last snapshot that has been replicated completely. Empty if the copy of the initial snapshot is not complete.
	LastSnapshotId pulumi.StringPtrInput
	// Additional information about the current 'lifecycleState'.
	LifecycleDetails pulumi.StringPtrInput
	// Locks associated with this resource.
	Locks ReplicationLockArrayInput
	// The [`snapshotTime`](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Snapshot/snapshotTime) of the most recent recoverable replication snapshot in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format. Example: `2021-04-04T20:01:29.100Z`
	RecoveryPointTime pulumi.StringPtrInput
	// (Updatable) Duration in minutes between replication snapshots.
	ReplicationInterval pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [`ReplicationTarget`](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ReplicationTarget).
	ReplicationTargetId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source file system.
	SourceId pulumi.StringPtrInput
	// The current state of this replication. This resource can be in a `FAILED` state if replication target is deleted instead of the replication resource.
	State pulumi.StringPtrInput
	// System tags for this resource. System tags are applied to resources by internal Oracle Cloud Infrastructure services.
	SystemTags pulumi.StringMapInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target file system.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TargetId pulumi.StringPtrInput
	// The date and time the replication was created in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2021-01-04T20:01:29.100Z`
	TimeCreated pulumi.StringPtrInput
}

func (ReplicationState) ElementType() reflect.Type {
	return reflect.TypeOf((*replicationState)(nil)).Elem()
}

type replicationArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the replication.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information. An associated replication target will also created with the same `displayName`. Example: `My replication`
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags   map[string]string `pulumi:"freeformTags"`
	IsLockOverride *bool             `pulumi:"isLockOverride"`
	// Locks associated with this resource.
	Locks []ReplicationLock `pulumi:"locks"`
	// (Updatable) Duration in minutes between replication snapshots.
	ReplicationInterval *string `pulumi:"replicationInterval"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source file system.
	SourceId string `pulumi:"sourceId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target file system.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TargetId string `pulumi:"targetId"`
}

// The set of arguments for constructing a Replication resource.
type ReplicationArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the replication.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information. An associated replication target will also created with the same `displayName`. Example: `My replication`
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags   pulumi.StringMapInput
	IsLockOverride pulumi.BoolPtrInput
	// Locks associated with this resource.
	Locks ReplicationLockArrayInput
	// (Updatable) Duration in minutes between replication snapshots.
	ReplicationInterval pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source file system.
	SourceId pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target file system.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TargetId pulumi.StringInput
}

func (ReplicationArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*replicationArgs)(nil)).Elem()
}

type ReplicationInput interface {
	pulumi.Input

	ToReplicationOutput() ReplicationOutput
	ToReplicationOutputWithContext(ctx context.Context) ReplicationOutput
}

func (*Replication) ElementType() reflect.Type {
	return reflect.TypeOf((**Replication)(nil)).Elem()
}

func (i *Replication) ToReplicationOutput() ReplicationOutput {
	return i.ToReplicationOutputWithContext(context.Background())
}

func (i *Replication) ToReplicationOutputWithContext(ctx context.Context) ReplicationOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ReplicationOutput)
}

// ReplicationArrayInput is an input type that accepts ReplicationArray and ReplicationArrayOutput values.
// You can construct a concrete instance of `ReplicationArrayInput` via:
//
//	ReplicationArray{ ReplicationArgs{...} }
type ReplicationArrayInput interface {
	pulumi.Input

	ToReplicationArrayOutput() ReplicationArrayOutput
	ToReplicationArrayOutputWithContext(context.Context) ReplicationArrayOutput
}

type ReplicationArray []ReplicationInput

func (ReplicationArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Replication)(nil)).Elem()
}

func (i ReplicationArray) ToReplicationArrayOutput() ReplicationArrayOutput {
	return i.ToReplicationArrayOutputWithContext(context.Background())
}

func (i ReplicationArray) ToReplicationArrayOutputWithContext(ctx context.Context) ReplicationArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ReplicationArrayOutput)
}

// ReplicationMapInput is an input type that accepts ReplicationMap and ReplicationMapOutput values.
// You can construct a concrete instance of `ReplicationMapInput` via:
//
//	ReplicationMap{ "key": ReplicationArgs{...} }
type ReplicationMapInput interface {
	pulumi.Input

	ToReplicationMapOutput() ReplicationMapOutput
	ToReplicationMapOutputWithContext(context.Context) ReplicationMapOutput
}

type ReplicationMap map[string]ReplicationInput

func (ReplicationMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Replication)(nil)).Elem()
}

func (i ReplicationMap) ToReplicationMapOutput() ReplicationMapOutput {
	return i.ToReplicationMapOutputWithContext(context.Background())
}

func (i ReplicationMap) ToReplicationMapOutputWithContext(ctx context.Context) ReplicationMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ReplicationMapOutput)
}

type ReplicationOutput struct{ *pulumi.OutputState }

func (ReplicationOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Replication)(nil)).Elem()
}

func (o ReplicationOutput) ToReplicationOutput() ReplicationOutput {
	return o
}

func (o ReplicationOutput) ToReplicationOutputWithContext(ctx context.Context) ReplicationOutput {
	return o
}

// The availability domain the replication is in. The replication must be in the same availability domain as the source file system. Example: `Uocm:PHX-AD-1`
func (o ReplicationOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringOutput { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the replication.
func (o ReplicationOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o ReplicationOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Percentage progress of the current replication cycle.
func (o ReplicationOutput) DeltaProgress() pulumi.StringOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringOutput { return v.DeltaProgress }).(pulumi.StringOutput)
}

// The current state of the snapshot during replication operations.
func (o ReplicationOutput) DeltaStatus() pulumi.StringOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringOutput { return v.DeltaStatus }).(pulumi.StringOutput)
}

// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information. An associated replication target will also created with the same `displayName`. Example: `My replication`
func (o ReplicationOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o ReplicationOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

func (o ReplicationOutput) IsLockOverride() pulumi.BoolOutput {
	return o.ApplyT(func(v *Replication) pulumi.BoolOutput { return v.IsLockOverride }).(pulumi.BoolOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last snapshot that has been replicated completely. Empty if the copy of the initial snapshot is not complete.
func (o ReplicationOutput) LastSnapshotId() pulumi.StringOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringOutput { return v.LastSnapshotId }).(pulumi.StringOutput)
}

// Additional information about the current 'lifecycleState'.
func (o ReplicationOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Locks associated with this resource.
func (o ReplicationOutput) Locks() ReplicationLockArrayOutput {
	return o.ApplyT(func(v *Replication) ReplicationLockArrayOutput { return v.Locks }).(ReplicationLockArrayOutput)
}

// The [`snapshotTime`](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Snapshot/snapshotTime) of the most recent recoverable replication snapshot in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format. Example: `2021-04-04T20:01:29.100Z`
func (o ReplicationOutput) RecoveryPointTime() pulumi.StringOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringOutput { return v.RecoveryPointTime }).(pulumi.StringOutput)
}

// (Updatable) Duration in minutes between replication snapshots.
func (o ReplicationOutput) ReplicationInterval() pulumi.StringOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringOutput { return v.ReplicationInterval }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [`ReplicationTarget`](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ReplicationTarget).
func (o ReplicationOutput) ReplicationTargetId() pulumi.StringOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringOutput { return v.ReplicationTargetId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source file system.
func (o ReplicationOutput) SourceId() pulumi.StringOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringOutput { return v.SourceId }).(pulumi.StringOutput)
}

// The current state of this replication. This resource can be in a `FAILED` state if replication target is deleted instead of the replication resource.
func (o ReplicationOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. System tags are applied to resources by internal Oracle Cloud Infrastructure services.
func (o ReplicationOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target file system.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ReplicationOutput) TargetId() pulumi.StringOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringOutput { return v.TargetId }).(pulumi.StringOutput)
}

// The date and time the replication was created in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2021-01-04T20:01:29.100Z`
func (o ReplicationOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Replication) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

type ReplicationArrayOutput struct{ *pulumi.OutputState }

func (ReplicationArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Replication)(nil)).Elem()
}

func (o ReplicationArrayOutput) ToReplicationArrayOutput() ReplicationArrayOutput {
	return o
}

func (o ReplicationArrayOutput) ToReplicationArrayOutputWithContext(ctx context.Context) ReplicationArrayOutput {
	return o
}

func (o ReplicationArrayOutput) Index(i pulumi.IntInput) ReplicationOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Replication {
		return vs[0].([]*Replication)[vs[1].(int)]
	}).(ReplicationOutput)
}

type ReplicationMapOutput struct{ *pulumi.OutputState }

func (ReplicationMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Replication)(nil)).Elem()
}

func (o ReplicationMapOutput) ToReplicationMapOutput() ReplicationMapOutput {
	return o
}

func (o ReplicationMapOutput) ToReplicationMapOutputWithContext(ctx context.Context) ReplicationMapOutput {
	return o
}

func (o ReplicationMapOutput) MapIndex(k pulumi.StringInput) ReplicationOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Replication {
		return vs[0].(map[string]*Replication)[vs[1].(string)]
	}).(ReplicationOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ReplicationInput)(nil)).Elem(), &Replication{})
	pulumi.RegisterInputType(reflect.TypeOf((*ReplicationArrayInput)(nil)).Elem(), ReplicationArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ReplicationMapInput)(nil)).Elem(), ReplicationMap{})
	pulumi.RegisterOutputType(ReplicationOutput{})
	pulumi.RegisterOutputType(ReplicationArrayOutput{})
	pulumi.RegisterOutputType(ReplicationMapOutput{})
}
