// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package devops

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Repository resource in Oracle Cloud Infrastructure Devops service.
//
// Creates a new repository.
//
// ## Import
//
// Repositories can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DevOps/repository:Repository test_repository "id"
// ```
type Repository struct {
	pulumi.CustomResourceState

	// The count of the branches present in the repository.
	BranchCount pulumi.IntOutput `pulumi:"branchCount"`
	// The count of the commits present in the repository.
	CommitCount pulumi.IntOutput `pulumi:"commitCount"`
	// The OCID of the repository's compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) The default branch of the repository.
	DefaultBranch pulumi.StringOutput `pulumi:"defaultBranch"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) Details of the repository. Avoid entering confidential information.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// HTTP URL that you use to git clone, pull and push.
	HttpUrl pulumi.StringOutput `pulumi:"httpUrl"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecyleDetails pulumi.StringOutput `pulumi:"lifecyleDetails"`
	// (Updatable) Configuration information for mirroring the repository.
	MirrorRepositoryConfig RepositoryMirrorRepositoryConfigOutput `pulumi:"mirrorRepositoryConfig"`
	// (Updatable) Name of the repository. Should be unique within the project.
	Name pulumi.StringOutput `pulumi:"name"`
	// Tenancy unique namespace.
	Namespace pulumi.StringOutput `pulumi:"namespace"`
	// The OCID of the parent repository.
	ParentRepositoryId pulumi.StringOutput `pulumi:"parentRepositoryId"`
	// The OCID of the DevOps project containing the repository.
	ProjectId pulumi.StringOutput `pulumi:"projectId"`
	// Unique project name in a namespace.
	ProjectName pulumi.StringOutput `pulumi:"projectName"`
	// (Updatable) Type of repository. Allowed values:  `MIRRORED`  `HOSTED` `FORKED`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	RepositoryType pulumi.StringOutput `pulumi:"repositoryType"`
	// The size of the repository in bytes.
	SizeInBytes pulumi.StringOutput `pulumi:"sizeInBytes"`
	// SSH URL that you use to git clone, pull and push.
	SshUrl pulumi.StringOutput `pulumi:"sshUrl"`
	// The current state of the repository.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The time the repository was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the repository was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// Trigger build events supported for this repository: PUSH - Build is triggered when a push event occurs. PULL_REQUEST_CREATED - Build is triggered when a pull request is created in the repository. PULL_REQUEST_UPDATED - Build is triggered when a push is made to a branch with an open pull request. COMMIT_UPDATES - Build is triggered when new commits are mirrored into a repository.
	TriggerBuildEvents pulumi.StringArrayOutput `pulumi:"triggerBuildEvents"`
}

// NewRepository registers a new resource with the given unique name, arguments, and options.
func NewRepository(ctx *pulumi.Context,
	name string, args *RepositoryArgs, opts ...pulumi.ResourceOption) (*Repository, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ProjectId == nil {
		return nil, errors.New("invalid value for required argument 'ProjectId'")
	}
	if args.RepositoryType == nil {
		return nil, errors.New("invalid value for required argument 'RepositoryType'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource Repository
	err := ctx.RegisterResource("oci:DevOps/repository:Repository", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetRepository gets an existing Repository resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetRepository(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *RepositoryState, opts ...pulumi.ResourceOption) (*Repository, error) {
	var resource Repository
	err := ctx.ReadResource("oci:DevOps/repository:Repository", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Repository resources.
type repositoryState struct {
	// The count of the branches present in the repository.
	BranchCount *int `pulumi:"branchCount"`
	// The count of the commits present in the repository.
	CommitCount *int `pulumi:"commitCount"`
	// The OCID of the repository's compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) The default branch of the repository.
	DefaultBranch *string `pulumi:"defaultBranch"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Details of the repository. Avoid entering confidential information.
	Description *string `pulumi:"description"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// HTTP URL that you use to git clone, pull and push.
	HttpUrl *string `pulumi:"httpUrl"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecyleDetails *string `pulumi:"lifecyleDetails"`
	// (Updatable) Configuration information for mirroring the repository.
	MirrorRepositoryConfig *RepositoryMirrorRepositoryConfig `pulumi:"mirrorRepositoryConfig"`
	// (Updatable) Name of the repository. Should be unique within the project.
	Name *string `pulumi:"name"`
	// Tenancy unique namespace.
	Namespace *string `pulumi:"namespace"`
	// The OCID of the parent repository.
	ParentRepositoryId *string `pulumi:"parentRepositoryId"`
	// The OCID of the DevOps project containing the repository.
	ProjectId *string `pulumi:"projectId"`
	// Unique project name in a namespace.
	ProjectName *string `pulumi:"projectName"`
	// (Updatable) Type of repository. Allowed values:  `MIRRORED`  `HOSTED` `FORKED`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	RepositoryType *string `pulumi:"repositoryType"`
	// The size of the repository in bytes.
	SizeInBytes *string `pulumi:"sizeInBytes"`
	// SSH URL that you use to git clone, pull and push.
	SshUrl *string `pulumi:"sshUrl"`
	// The current state of the repository.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time the repository was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the repository was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated *string `pulumi:"timeUpdated"`
	// Trigger build events supported for this repository: PUSH - Build is triggered when a push event occurs. PULL_REQUEST_CREATED - Build is triggered when a pull request is created in the repository. PULL_REQUEST_UPDATED - Build is triggered when a push is made to a branch with an open pull request. COMMIT_UPDATES - Build is triggered when new commits are mirrored into a repository.
	TriggerBuildEvents []string `pulumi:"triggerBuildEvents"`
}

type RepositoryState struct {
	// The count of the branches present in the repository.
	BranchCount pulumi.IntPtrInput
	// The count of the commits present in the repository.
	CommitCount pulumi.IntPtrInput
	// The OCID of the repository's compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) The default branch of the repository.
	DefaultBranch pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Details of the repository. Avoid entering confidential information.
	Description pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// HTTP URL that you use to git clone, pull and push.
	HttpUrl pulumi.StringPtrInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecyleDetails pulumi.StringPtrInput
	// (Updatable) Configuration information for mirroring the repository.
	MirrorRepositoryConfig RepositoryMirrorRepositoryConfigPtrInput
	// (Updatable) Name of the repository. Should be unique within the project.
	Name pulumi.StringPtrInput
	// Tenancy unique namespace.
	Namespace pulumi.StringPtrInput
	// The OCID of the parent repository.
	ParentRepositoryId pulumi.StringPtrInput
	// The OCID of the DevOps project containing the repository.
	ProjectId pulumi.StringPtrInput
	// Unique project name in a namespace.
	ProjectName pulumi.StringPtrInput
	// (Updatable) Type of repository. Allowed values:  `MIRRORED`  `HOSTED` `FORKED`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	RepositoryType pulumi.StringPtrInput
	// The size of the repository in bytes.
	SizeInBytes pulumi.StringPtrInput
	// SSH URL that you use to git clone, pull and push.
	SshUrl pulumi.StringPtrInput
	// The current state of the repository.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The time the repository was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// The time the repository was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated pulumi.StringPtrInput
	// Trigger build events supported for this repository: PUSH - Build is triggered when a push event occurs. PULL_REQUEST_CREATED - Build is triggered when a pull request is created in the repository. PULL_REQUEST_UPDATED - Build is triggered when a push is made to a branch with an open pull request. COMMIT_UPDATES - Build is triggered when new commits are mirrored into a repository.
	TriggerBuildEvents pulumi.StringArrayInput
}

func (RepositoryState) ElementType() reflect.Type {
	return reflect.TypeOf((*repositoryState)(nil)).Elem()
}

type repositoryArgs struct {
	// (Updatable) The default branch of the repository.
	DefaultBranch *string `pulumi:"defaultBranch"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Details of the repository. Avoid entering confidential information.
	Description *string `pulumi:"description"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) Configuration information for mirroring the repository.
	MirrorRepositoryConfig *RepositoryMirrorRepositoryConfig `pulumi:"mirrorRepositoryConfig"`
	// (Updatable) Name of the repository. Should be unique within the project.
	Name *string `pulumi:"name"`
	// The OCID of the parent repository.
	ParentRepositoryId *string `pulumi:"parentRepositoryId"`
	// The OCID of the DevOps project containing the repository.
	ProjectId string `pulumi:"projectId"`
	// (Updatable) Type of repository. Allowed values:  `MIRRORED`  `HOSTED` `FORKED`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	RepositoryType string `pulumi:"repositoryType"`
}

// The set of arguments for constructing a Repository resource.
type RepositoryArgs struct {
	// (Updatable) The default branch of the repository.
	DefaultBranch pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Details of the repository. Avoid entering confidential information.
	Description pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) Configuration information for mirroring the repository.
	MirrorRepositoryConfig RepositoryMirrorRepositoryConfigPtrInput
	// (Updatable) Name of the repository. Should be unique within the project.
	Name pulumi.StringPtrInput
	// The OCID of the parent repository.
	ParentRepositoryId pulumi.StringPtrInput
	// The OCID of the DevOps project containing the repository.
	ProjectId pulumi.StringInput
	// (Updatable) Type of repository. Allowed values:  `MIRRORED`  `HOSTED` `FORKED`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	RepositoryType pulumi.StringInput
}

func (RepositoryArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*repositoryArgs)(nil)).Elem()
}

type RepositoryInput interface {
	pulumi.Input

	ToRepositoryOutput() RepositoryOutput
	ToRepositoryOutputWithContext(ctx context.Context) RepositoryOutput
}

func (*Repository) ElementType() reflect.Type {
	return reflect.TypeOf((**Repository)(nil)).Elem()
}

func (i *Repository) ToRepositoryOutput() RepositoryOutput {
	return i.ToRepositoryOutputWithContext(context.Background())
}

func (i *Repository) ToRepositoryOutputWithContext(ctx context.Context) RepositoryOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RepositoryOutput)
}

// RepositoryArrayInput is an input type that accepts RepositoryArray and RepositoryArrayOutput values.
// You can construct a concrete instance of `RepositoryArrayInput` via:
//
//	RepositoryArray{ RepositoryArgs{...} }
type RepositoryArrayInput interface {
	pulumi.Input

	ToRepositoryArrayOutput() RepositoryArrayOutput
	ToRepositoryArrayOutputWithContext(context.Context) RepositoryArrayOutput
}

type RepositoryArray []RepositoryInput

func (RepositoryArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Repository)(nil)).Elem()
}

func (i RepositoryArray) ToRepositoryArrayOutput() RepositoryArrayOutput {
	return i.ToRepositoryArrayOutputWithContext(context.Background())
}

func (i RepositoryArray) ToRepositoryArrayOutputWithContext(ctx context.Context) RepositoryArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RepositoryArrayOutput)
}

// RepositoryMapInput is an input type that accepts RepositoryMap and RepositoryMapOutput values.
// You can construct a concrete instance of `RepositoryMapInput` via:
//
//	RepositoryMap{ "key": RepositoryArgs{...} }
type RepositoryMapInput interface {
	pulumi.Input

	ToRepositoryMapOutput() RepositoryMapOutput
	ToRepositoryMapOutputWithContext(context.Context) RepositoryMapOutput
}

type RepositoryMap map[string]RepositoryInput

func (RepositoryMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Repository)(nil)).Elem()
}

func (i RepositoryMap) ToRepositoryMapOutput() RepositoryMapOutput {
	return i.ToRepositoryMapOutputWithContext(context.Background())
}

func (i RepositoryMap) ToRepositoryMapOutputWithContext(ctx context.Context) RepositoryMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RepositoryMapOutput)
}

type RepositoryOutput struct{ *pulumi.OutputState }

func (RepositoryOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Repository)(nil)).Elem()
}

func (o RepositoryOutput) ToRepositoryOutput() RepositoryOutput {
	return o
}

func (o RepositoryOutput) ToRepositoryOutputWithContext(ctx context.Context) RepositoryOutput {
	return o
}

// The count of the branches present in the repository.
func (o RepositoryOutput) BranchCount() pulumi.IntOutput {
	return o.ApplyT(func(v *Repository) pulumi.IntOutput { return v.BranchCount }).(pulumi.IntOutput)
}

// The count of the commits present in the repository.
func (o RepositoryOutput) CommitCount() pulumi.IntOutput {
	return o.ApplyT(func(v *Repository) pulumi.IntOutput { return v.CommitCount }).(pulumi.IntOutput)
}

// The OCID of the repository's compartment.
func (o RepositoryOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) The default branch of the repository.
func (o RepositoryOutput) DefaultBranch() pulumi.StringOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringOutput { return v.DefaultBranch }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
func (o RepositoryOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) Details of the repository. Avoid entering confidential information.
func (o RepositoryOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
func (o RepositoryOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// HTTP URL that you use to git clone, pull and push.
func (o RepositoryOutput) HttpUrl() pulumi.StringOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringOutput { return v.HttpUrl }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o RepositoryOutput) LifecyleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringOutput { return v.LifecyleDetails }).(pulumi.StringOutput)
}

// (Updatable) Configuration information for mirroring the repository.
func (o RepositoryOutput) MirrorRepositoryConfig() RepositoryMirrorRepositoryConfigOutput {
	return o.ApplyT(func(v *Repository) RepositoryMirrorRepositoryConfigOutput { return v.MirrorRepositoryConfig }).(RepositoryMirrorRepositoryConfigOutput)
}

// (Updatable) Name of the repository. Should be unique within the project.
func (o RepositoryOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// Tenancy unique namespace.
func (o RepositoryOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringOutput { return v.Namespace }).(pulumi.StringOutput)
}

// The OCID of the parent repository.
func (o RepositoryOutput) ParentRepositoryId() pulumi.StringOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringOutput { return v.ParentRepositoryId }).(pulumi.StringOutput)
}

// The OCID of the DevOps project containing the repository.
func (o RepositoryOutput) ProjectId() pulumi.StringOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringOutput { return v.ProjectId }).(pulumi.StringOutput)
}

// Unique project name in a namespace.
func (o RepositoryOutput) ProjectName() pulumi.StringOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringOutput { return v.ProjectName }).(pulumi.StringOutput)
}

// (Updatable) Type of repository. Allowed values:  `MIRRORED`  `HOSTED` `FORKED`
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o RepositoryOutput) RepositoryType() pulumi.StringOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringOutput { return v.RepositoryType }).(pulumi.StringOutput)
}

// The size of the repository in bytes.
func (o RepositoryOutput) SizeInBytes() pulumi.StringOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringOutput { return v.SizeInBytes }).(pulumi.StringOutput)
}

// SSH URL that you use to git clone, pull and push.
func (o RepositoryOutput) SshUrl() pulumi.StringOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringOutput { return v.SshUrl }).(pulumi.StringOutput)
}

// The current state of the repository.
func (o RepositoryOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o RepositoryOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time the repository was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
func (o RepositoryOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the repository was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
func (o RepositoryOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// Trigger build events supported for this repository: PUSH - Build is triggered when a push event occurs. PULL_REQUEST_CREATED - Build is triggered when a pull request is created in the repository. PULL_REQUEST_UPDATED - Build is triggered when a push is made to a branch with an open pull request. COMMIT_UPDATES - Build is triggered when new commits are mirrored into a repository.
func (o RepositoryOutput) TriggerBuildEvents() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *Repository) pulumi.StringArrayOutput { return v.TriggerBuildEvents }).(pulumi.StringArrayOutput)
}

type RepositoryArrayOutput struct{ *pulumi.OutputState }

func (RepositoryArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Repository)(nil)).Elem()
}

func (o RepositoryArrayOutput) ToRepositoryArrayOutput() RepositoryArrayOutput {
	return o
}

func (o RepositoryArrayOutput) ToRepositoryArrayOutputWithContext(ctx context.Context) RepositoryArrayOutput {
	return o
}

func (o RepositoryArrayOutput) Index(i pulumi.IntInput) RepositoryOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Repository {
		return vs[0].([]*Repository)[vs[1].(int)]
	}).(RepositoryOutput)
}

type RepositoryMapOutput struct{ *pulumi.OutputState }

func (RepositoryMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Repository)(nil)).Elem()
}

func (o RepositoryMapOutput) ToRepositoryMapOutput() RepositoryMapOutput {
	return o
}

func (o RepositoryMapOutput) ToRepositoryMapOutputWithContext(ctx context.Context) RepositoryMapOutput {
	return o
}

func (o RepositoryMapOutput) MapIndex(k pulumi.StringInput) RepositoryOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Repository {
		return vs[0].(map[string]*Repository)[vs[1].(string)]
	}).(RepositoryOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*RepositoryInput)(nil)).Elem(), &Repository{})
	pulumi.RegisterInputType(reflect.TypeOf((*RepositoryArrayInput)(nil)).Elem(), RepositoryArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*RepositoryMapInput)(nil)).Elem(), RepositoryMap{})
	pulumi.RegisterOutputType(RepositoryOutput{})
	pulumi.RegisterOutputType(RepositoryArrayOutput{})
	pulumi.RegisterOutputType(RepositoryMapOutput{})
}
