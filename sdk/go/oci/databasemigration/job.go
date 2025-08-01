// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemigration

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// ## Example Usage
//
// ## Import
//
// Jobs can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DatabaseMigration/job:Job test_job "id"
// ```
type Job struct {
	pulumi.CustomResourceState

	// Information regarding the DB trace and alert log collection
	CollectTracesDatas JobCollectTracesDataArrayOutput `pulumi:"collectTracesDatas"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) Name of the job.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see Resource Tags. Example: {"Department": "Finance"}
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// The OCID of the job
	JobId pulumi.StringOutput `pulumi:"jobId"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The OCID of the Migration that this job belongs to.
	MigrationId pulumi.StringOutput `pulumi:"migrationId"`
	// A list of parameter file versions that can be viewed or edited for the current job.
	ParameterFileVersions JobParameterFileVersionArrayOutput `pulumi:"parameterFileVersions"`
	// Percent progress of job phase.
	Progresses JobProgressArrayOutput `pulumi:"progresses"`
	// The current state of the migration job.
	State pulumi.StringOutput `pulumi:"state"`
	// (Updatable) An optional property when incremented triggers Suspend. Could be set to any integer value.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SuspendTrigger pulumi.IntPtrOutput `pulumi:"suspendTrigger"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The time the Migration Job was created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the Migration Job was last updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// Type of unsupported object
	Type pulumi.StringOutput `pulumi:"type"`
	// Database objects not supported.
	UnsupportedObjects JobUnsupportedObjectArrayOutput `pulumi:"unsupportedObjects"`
}

// NewJob registers a new resource with the given unique name, arguments, and options.
func NewJob(ctx *pulumi.Context,
	name string, args *JobArgs, opts ...pulumi.ResourceOption) (*Job, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.JobId == nil {
		return nil, errors.New("invalid value for required argument 'JobId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource Job
	err := ctx.RegisterResource("oci:DatabaseMigration/job:Job", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetJob gets an existing Job resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetJob(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *JobState, opts ...pulumi.ResourceOption) (*Job, error) {
	var resource Job
	err := ctx.ReadResource("oci:DatabaseMigration/job:Job", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Job resources.
type jobState struct {
	// Information regarding the DB trace and alert log collection
	CollectTracesDatas []JobCollectTracesData `pulumi:"collectTracesDatas"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Name of the job.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see Resource Tags. Example: {"Department": "Finance"}
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the job
	JobId *string `pulumi:"jobId"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The OCID of the Migration that this job belongs to.
	MigrationId *string `pulumi:"migrationId"`
	// A list of parameter file versions that can be viewed or edited for the current job.
	ParameterFileVersions []JobParameterFileVersion `pulumi:"parameterFileVersions"`
	// Percent progress of job phase.
	Progresses []JobProgress `pulumi:"progresses"`
	// The current state of the migration job.
	State *string `pulumi:"state"`
	// (Updatable) An optional property when incremented triggers Suspend. Could be set to any integer value.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SuspendTrigger *int `pulumi:"suspendTrigger"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time the Migration Job was created. An RFC3339 formatted datetime string
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the Migration Job was last updated. An RFC3339 formatted datetime string
	TimeUpdated *string `pulumi:"timeUpdated"`
	// Type of unsupported object
	Type *string `pulumi:"type"`
	// Database objects not supported.
	UnsupportedObjects []JobUnsupportedObject `pulumi:"unsupportedObjects"`
}

type JobState struct {
	// Information regarding the DB trace and alert log collection
	CollectTracesDatas JobCollectTracesDataArrayInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Name of the job.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see Resource Tags. Example: {"Department": "Finance"}
	FreeformTags pulumi.StringMapInput
	// The OCID of the job
	JobId pulumi.StringPtrInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// The OCID of the Migration that this job belongs to.
	MigrationId pulumi.StringPtrInput
	// A list of parameter file versions that can be viewed or edited for the current job.
	ParameterFileVersions JobParameterFileVersionArrayInput
	// Percent progress of job phase.
	Progresses JobProgressArrayInput
	// The current state of the migration job.
	State pulumi.StringPtrInput
	// (Updatable) An optional property when incremented triggers Suspend. Could be set to any integer value.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SuspendTrigger pulumi.IntPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The time the Migration Job was created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringPtrInput
	// The time the Migration Job was last updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringPtrInput
	// Type of unsupported object
	Type pulumi.StringPtrInput
	// Database objects not supported.
	UnsupportedObjects JobUnsupportedObjectArrayInput
}

func (JobState) ElementType() reflect.Type {
	return reflect.TypeOf((*jobState)(nil)).Elem()
}

type jobArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Name of the job.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see Resource Tags. Example: {"Department": "Finance"}
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the job
	JobId string `pulumi:"jobId"`
	// (Updatable) An optional property when incremented triggers Suspend. Could be set to any integer value.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SuspendTrigger *int `pulumi:"suspendTrigger"`
}

// The set of arguments for constructing a Job resource.
type JobArgs struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Name of the job.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see Resource Tags. Example: {"Department": "Finance"}
	FreeformTags pulumi.StringMapInput
	// The OCID of the job
	JobId pulumi.StringInput
	// (Updatable) An optional property when incremented triggers Suspend. Could be set to any integer value.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SuspendTrigger pulumi.IntPtrInput
}

func (JobArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*jobArgs)(nil)).Elem()
}

type JobInput interface {
	pulumi.Input

	ToJobOutput() JobOutput
	ToJobOutputWithContext(ctx context.Context) JobOutput
}

func (*Job) ElementType() reflect.Type {
	return reflect.TypeOf((**Job)(nil)).Elem()
}

func (i *Job) ToJobOutput() JobOutput {
	return i.ToJobOutputWithContext(context.Background())
}

func (i *Job) ToJobOutputWithContext(ctx context.Context) JobOutput {
	return pulumi.ToOutputWithContext(ctx, i).(JobOutput)
}

// JobArrayInput is an input type that accepts JobArray and JobArrayOutput values.
// You can construct a concrete instance of `JobArrayInput` via:
//
//	JobArray{ JobArgs{...} }
type JobArrayInput interface {
	pulumi.Input

	ToJobArrayOutput() JobArrayOutput
	ToJobArrayOutputWithContext(context.Context) JobArrayOutput
}

type JobArray []JobInput

func (JobArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Job)(nil)).Elem()
}

func (i JobArray) ToJobArrayOutput() JobArrayOutput {
	return i.ToJobArrayOutputWithContext(context.Background())
}

func (i JobArray) ToJobArrayOutputWithContext(ctx context.Context) JobArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(JobArrayOutput)
}

// JobMapInput is an input type that accepts JobMap and JobMapOutput values.
// You can construct a concrete instance of `JobMapInput` via:
//
//	JobMap{ "key": JobArgs{...} }
type JobMapInput interface {
	pulumi.Input

	ToJobMapOutput() JobMapOutput
	ToJobMapOutputWithContext(context.Context) JobMapOutput
}

type JobMap map[string]JobInput

func (JobMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Job)(nil)).Elem()
}

func (i JobMap) ToJobMapOutput() JobMapOutput {
	return i.ToJobMapOutputWithContext(context.Background())
}

func (i JobMap) ToJobMapOutputWithContext(ctx context.Context) JobMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(JobMapOutput)
}

type JobOutput struct{ *pulumi.OutputState }

func (JobOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Job)(nil)).Elem()
}

func (o JobOutput) ToJobOutput() JobOutput {
	return o
}

func (o JobOutput) ToJobOutputWithContext(ctx context.Context) JobOutput {
	return o
}

// Information regarding the DB trace and alert log collection
func (o JobOutput) CollectTracesDatas() JobCollectTracesDataArrayOutput {
	return o.ApplyT(func(v *Job) JobCollectTracesDataArrayOutput { return v.CollectTracesDatas }).(JobCollectTracesDataArrayOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o JobOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Job) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) Name of the job.
func (o JobOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *Job) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see Resource Tags. Example: {"Department": "Finance"}
func (o JobOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Job) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The OCID of the job
func (o JobOutput) JobId() pulumi.StringOutput {
	return o.ApplyT(func(v *Job) pulumi.StringOutput { return v.JobId }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o JobOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *Job) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The OCID of the Migration that this job belongs to.
func (o JobOutput) MigrationId() pulumi.StringOutput {
	return o.ApplyT(func(v *Job) pulumi.StringOutput { return v.MigrationId }).(pulumi.StringOutput)
}

// A list of parameter file versions that can be viewed or edited for the current job.
func (o JobOutput) ParameterFileVersions() JobParameterFileVersionArrayOutput {
	return o.ApplyT(func(v *Job) JobParameterFileVersionArrayOutput { return v.ParameterFileVersions }).(JobParameterFileVersionArrayOutput)
}

// Percent progress of job phase.
func (o JobOutput) Progresses() JobProgressArrayOutput {
	return o.ApplyT(func(v *Job) JobProgressArrayOutput { return v.Progresses }).(JobProgressArrayOutput)
}

// The current state of the migration job.
func (o JobOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Job) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// (Updatable) An optional property when incremented triggers Suspend. Could be set to any integer value.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o JobOutput) SuspendTrigger() pulumi.IntPtrOutput {
	return o.ApplyT(func(v *Job) pulumi.IntPtrOutput { return v.SuspendTrigger }).(pulumi.IntPtrOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o JobOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Job) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time the Migration Job was created. An RFC3339 formatted datetime string
func (o JobOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Job) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the Migration Job was last updated. An RFC3339 formatted datetime string
func (o JobOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *Job) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// Type of unsupported object
func (o JobOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v *Job) pulumi.StringOutput { return v.Type }).(pulumi.StringOutput)
}

// Database objects not supported.
func (o JobOutput) UnsupportedObjects() JobUnsupportedObjectArrayOutput {
	return o.ApplyT(func(v *Job) JobUnsupportedObjectArrayOutput { return v.UnsupportedObjects }).(JobUnsupportedObjectArrayOutput)
}

type JobArrayOutput struct{ *pulumi.OutputState }

func (JobArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Job)(nil)).Elem()
}

func (o JobArrayOutput) ToJobArrayOutput() JobArrayOutput {
	return o
}

func (o JobArrayOutput) ToJobArrayOutputWithContext(ctx context.Context) JobArrayOutput {
	return o
}

func (o JobArrayOutput) Index(i pulumi.IntInput) JobOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Job {
		return vs[0].([]*Job)[vs[1].(int)]
	}).(JobOutput)
}

type JobMapOutput struct{ *pulumi.OutputState }

func (JobMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Job)(nil)).Elem()
}

func (o JobMapOutput) ToJobMapOutput() JobMapOutput {
	return o
}

func (o JobMapOutput) ToJobMapOutputWithContext(ctx context.Context) JobMapOutput {
	return o
}

func (o JobMapOutput) MapIndex(k pulumi.StringInput) JobOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Job {
		return vs[0].(map[string]*Job)[vs[1].(string)]
	}).(JobOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*JobInput)(nil)).Elem(), &Job{})
	pulumi.RegisterInputType(reflect.TypeOf((*JobArrayInput)(nil)).Elem(), JobArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*JobMapInput)(nil)).Elem(), JobMap{})
	pulumi.RegisterOutputType(JobOutput{})
	pulumi.RegisterOutputType(JobArrayOutput{})
	pulumi.RegisterOutputType(JobMapOutput{})
}
