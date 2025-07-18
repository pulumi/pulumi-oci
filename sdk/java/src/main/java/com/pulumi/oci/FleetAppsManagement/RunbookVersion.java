// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.FleetAppsManagement.RunbookVersionArgs;
import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionState;
import com.pulumi.oci.FleetAppsManagement.outputs.RunbookVersionExecutionWorkflowDetails;
import com.pulumi.oci.FleetAppsManagement.outputs.RunbookVersionGroup;
import com.pulumi.oci.FleetAppsManagement.outputs.RunbookVersionRollbackWorkflowDetails;
import com.pulumi.oci.FleetAppsManagement.outputs.RunbookVersionTask;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Runbook Version resource in Oracle Cloud Infrastructure Fleet Apps Management service.
 * 
 * Add RunbookVersion in Fleet Application Management.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * <pre>
 * {@code
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.FleetAppsManagement.RunbookVersion;
 * import com.pulumi.oci.FleetAppsManagement.RunbookVersionArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionExecutionWorkflowDetailsArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionGroupArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionGroupPropertiesArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionGroupPropertiesNotificationPreferencesArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionGroupPropertiesPauseDetailsArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionGroupPropertiesRunOnArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionTaskArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionTaskTaskRecordDetailsArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionTaskTaskRecordDetailsExecutionDetailsArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionTaskTaskRecordDetailsExecutionDetailsContentArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionTaskTaskRecordDetailsExecutionDetailsVariablesArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionTaskTaskRecordDetailsPropertiesArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionTaskStepPropertiesArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionTaskStepPropertiesNotificationPreferencesArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionTaskStepPropertiesPauseDetailsArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionTaskStepPropertiesRunOnArgs;
 * import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionRollbackWorkflowDetailsArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var testRunbookVersion = new RunbookVersion("testRunbookVersion", RunbookVersionArgs.builder()
 *             .executionWorkflowDetails(RunbookVersionExecutionWorkflowDetailsArgs.builder()
 *                 .workflows(RunbookVersionExecutionWorkflowDetailsWorkflowArgs.builder()
 *                     .groupName(testGroup.name())
 *                     .steps(RunbookVersionExecutionWorkflowDetailsWorkflowStepArgs.builder()
 *                         .type(runbookVersionExecutionWorkflowDetailsWorkflowStepsType)
 *                         .groupName(testGroup.name())
 *                         .stepName(runbookVersionExecutionWorkflowDetailsWorkflowStepsStepName)
 *                         .steps(runbookVersionExecutionWorkflowDetailsWorkflowStepsSteps)
 *                         .build())
 *                     .type(runbookVersionExecutionWorkflowDetailsWorkflowType)
 *                     .build())
 *                 .build())
 *             .groups(RunbookVersionGroupArgs.builder()
 *                 .name(runbookVersionGroupsName)
 *                 .type(runbookVersionGroupsType)
 *                 .properties(RunbookVersionGroupPropertiesArgs.builder()
 *                     .actionOnFailure(runbookVersionGroupsPropertiesActionOnFailure)
 *                     .notificationPreferences(RunbookVersionGroupPropertiesNotificationPreferencesArgs.builder()
 *                         .shouldNotifyOnPause(runbookVersionGroupsPropertiesNotificationPreferencesShouldNotifyOnPause)
 *                         .shouldNotifyOnTaskFailure(runbookVersionGroupsPropertiesNotificationPreferencesShouldNotifyOnTaskFailure)
 *                         .shouldNotifyOnTaskSuccess(runbookVersionGroupsPropertiesNotificationPreferencesShouldNotifyOnTaskSuccess)
 *                         .build())
 *                     .pauseDetails(RunbookVersionGroupPropertiesPauseDetailsArgs.builder()
 *                         .kind(runbookVersionGroupsPropertiesPauseDetailsKind)
 *                         .durationInMinutes(runbookVersionGroupsPropertiesPauseDetailsDurationInMinutes)
 *                         .build())
 *                     .preCondition(runbookVersionGroupsPropertiesPreCondition)
 *                     .runOn(RunbookVersionGroupPropertiesRunOnArgs.builder()
 *                         .kind(runbookVersionGroupsPropertiesRunOnKind)
 *                         .condition(runbookVersionGroupsPropertiesRunOnCondition)
 *                         .host(runbookVersionGroupsPropertiesRunOnHost)
 *                         .previousTaskInstanceDetails(RunbookVersionGroupPropertiesRunOnPreviousTaskInstanceDetailArgs.builder()
 *                             .outputVariableDetails(RunbookVersionGroupPropertiesRunOnPreviousTaskInstanceDetailOutputVariableDetailsArgs.builder()
 *                                 .outputVariableName(runbookVersionGroupsPropertiesRunOnPreviousTaskInstanceDetailsOutputVariableDetailsOutputVariableName)
 *                                 .stepName(runbookVersionGroupsPropertiesRunOnPreviousTaskInstanceDetailsOutputVariableDetailsStepName)
 *                                 .build())
 *                             .resourceId(testResource.id())
 *                             .resourceType(runbookVersionGroupsPropertiesRunOnPreviousTaskInstanceDetailsResourceType)
 *                             .build())
 *                         .build())
 *                     .build())
 *                 .build())
 *             .runbookId(testRunbook.id())
 *             .tasks(RunbookVersionTaskArgs.builder()
 *                 .stepName(runbookVersionTasksStepName)
 *                 .taskRecordDetails(RunbookVersionTaskTaskRecordDetailsArgs.builder()
 *                     .scope(runbookVersionTasksTaskRecordDetailsScope)
 *                     .description(runbookVersionTasksTaskRecordDetailsDescription)
 *                     .executionDetails(RunbookVersionTaskTaskRecordDetailsExecutionDetailsArgs.builder()
 *                         .executionType(runbookVersionTasksTaskRecordDetailsExecutionDetailsExecutionType)
 *                         .catalogId(testCatalog.id())
 *                         .command(runbookVersionTasksTaskRecordDetailsExecutionDetailsCommand)
 *                         .configFile(runbookVersionTasksTaskRecordDetailsExecutionDetailsConfigFile)
 *                         .content(RunbookVersionTaskTaskRecordDetailsExecutionDetailsContentArgs.builder()
 *                             .sourceType(runbookVersionTasksTaskRecordDetailsExecutionDetailsContentSourceType)
 *                             .bucket(runbookVersionTasksTaskRecordDetailsExecutionDetailsContentBucket)
 *                             .catalogId(testCatalog.id())
 *                             .checksum(runbookVersionTasksTaskRecordDetailsExecutionDetailsContentChecksum)
 *                             .namespace(runbookVersionTasksTaskRecordDetailsExecutionDetailsContentNamespace)
 *                             .object(runbookVersionTasksTaskRecordDetailsExecutionDetailsContentObject)
 *                             .build())
 *                         .credentials(RunbookVersionTaskTaskRecordDetailsExecutionDetailsCredentialArgs.builder()
 *                             .displayName(runbookVersionTasksTaskRecordDetailsExecutionDetailsCredentialsDisplayName)
 *                             .id(runbookVersionTasksTaskRecordDetailsExecutionDetailsCredentialsId)
 *                             .build())
 *                         .endpoint(runbookVersionTasksTaskRecordDetailsExecutionDetailsEndpoint)
 *                         .isExecutableContent(runbookVersionTasksTaskRecordDetailsExecutionDetailsIsExecutableContent)
 *                         .isLocked(runbookVersionTasksTaskRecordDetailsExecutionDetailsIsLocked)
 *                         .isReadOutputVariableEnabled(runbookVersionTasksTaskRecordDetailsExecutionDetailsIsReadOutputVariableEnabled)
 *                         .targetCompartmentId(testCompartment.id())
 *                         .variables(RunbookVersionTaskTaskRecordDetailsExecutionDetailsVariablesArgs.builder()
 *                             .inputVariables(RunbookVersionTaskTaskRecordDetailsExecutionDetailsVariablesInputVariableArgs.builder()
 *                                 .description(runbookVersionTasksTaskRecordDetailsExecutionDetailsVariablesInputVariablesDescription)
 *                                 .name(runbookVersionTasksTaskRecordDetailsExecutionDetailsVariablesInputVariablesName)
 *                                 .type(runbookVersionTasksTaskRecordDetailsExecutionDetailsVariablesInputVariablesType)
 *                                 .build())
 *                             .outputVariables(runbookVersionTasksTaskRecordDetailsExecutionDetailsVariablesOutputVariables)
 *                             .build())
 *                         .build())
 *                     .isApplySubjectTask(runbookVersionTasksTaskRecordDetailsIsApplySubjectTask)
 *                     .isCopyToLibraryEnabled(runbookVersionTasksTaskRecordDetailsIsCopyToLibraryEnabled)
 *                     .isDiscoveryOutputTask(runbookVersionTasksTaskRecordDetailsIsDiscoveryOutputTask)
 *                     .name(runbookVersionTasksTaskRecordDetailsName)
 *                     .osType(runbookVersionTasksTaskRecordDetailsOsType)
 *                     .platform(runbookVersionTasksTaskRecordDetailsPlatform)
 *                     .properties(RunbookVersionTaskTaskRecordDetailsPropertiesArgs.builder()
 *                         .numRetries(runbookVersionTasksTaskRecordDetailsPropertiesNumRetries)
 *                         .timeoutInSeconds(runbookVersionTasksTaskRecordDetailsPropertiesTimeoutInSeconds)
 *                         .build())
 *                     .taskRecordId(testTaskRecord.id())
 *                     .build())
 *                 .outputVariableMappings(RunbookVersionTaskOutputVariableMappingArgs.builder()
 *                     .name(runbookVersionTasksOutputVariableMappingsName)
 *                     .outputVariableDetails(RunbookVersionTaskOutputVariableMappingOutputVariableDetailsArgs.builder()
 *                         .outputVariableName(runbookVersionTasksOutputVariableMappingsOutputVariableDetailsOutputVariableName)
 *                         .stepName(runbookVersionTasksOutputVariableMappingsOutputVariableDetailsStepName)
 *                         .build())
 *                     .build())
 *                 .stepProperties(RunbookVersionTaskStepPropertiesArgs.builder()
 *                     .actionOnFailure(runbookVersionTasksStepPropertiesActionOnFailure)
 *                     .notificationPreferences(RunbookVersionTaskStepPropertiesNotificationPreferencesArgs.builder()
 *                         .shouldNotifyOnPause(runbookVersionTasksStepPropertiesNotificationPreferencesShouldNotifyOnPause)
 *                         .shouldNotifyOnTaskFailure(runbookVersionTasksStepPropertiesNotificationPreferencesShouldNotifyOnTaskFailure)
 *                         .shouldNotifyOnTaskSuccess(runbookVersionTasksStepPropertiesNotificationPreferencesShouldNotifyOnTaskSuccess)
 *                         .build())
 *                     .pauseDetails(RunbookVersionTaskStepPropertiesPauseDetailsArgs.builder()
 *                         .kind(runbookVersionTasksStepPropertiesPauseDetailsKind)
 *                         .durationInMinutes(runbookVersionTasksStepPropertiesPauseDetailsDurationInMinutes)
 *                         .build())
 *                     .preCondition(runbookVersionTasksStepPropertiesPreCondition)
 *                     .runOn(RunbookVersionTaskStepPropertiesRunOnArgs.builder()
 *                         .kind(runbookVersionTasksStepPropertiesRunOnKind)
 *                         .condition(runbookVersionTasksStepPropertiesRunOnCondition)
 *                         .host(runbookVersionTasksStepPropertiesRunOnHost)
 *                         .previousTaskInstanceDetails(RunbookVersionTaskStepPropertiesRunOnPreviousTaskInstanceDetailArgs.builder()
 *                             .outputVariableDetails(RunbookVersionTaskStepPropertiesRunOnPreviousTaskInstanceDetailOutputVariableDetailsArgs.builder()
 *                                 .outputVariableName(runbookVersionTasksStepPropertiesRunOnPreviousTaskInstanceDetailsOutputVariableDetailsOutputVariableName)
 *                                 .stepName(runbookVersionTasksStepPropertiesRunOnPreviousTaskInstanceDetailsOutputVariableDetailsStepName)
 *                                 .build())
 *                             .resourceId(testResource.id())
 *                             .resourceType(runbookVersionTasksStepPropertiesRunOnPreviousTaskInstanceDetailsResourceType)
 *                             .build())
 *                         .build())
 *                     .build())
 *                 .build())
 *             .definedTags(Map.of("foo-namespace.bar-key", "value"))
 *             .freeformTags(Map.of("bar-key", "value"))
 *             .rollbackWorkflowDetails(RunbookVersionRollbackWorkflowDetailsArgs.builder()
 *                 .scope(runbookVersionRollbackWorkflowDetailsScope)
 *                 .workflows(RunbookVersionRollbackWorkflowDetailsWorkflowArgs.builder()
 *                     .groupName(testGroup.name())
 *                     .steps(RunbookVersionRollbackWorkflowDetailsWorkflowStepArgs.builder()
 *                         .type(runbookVersionRollbackWorkflowDetailsWorkflowStepsType)
 *                         .groupName(testGroup.name())
 *                         .stepName(runbookVersionRollbackWorkflowDetailsWorkflowStepsStepName)
 *                         .steps(runbookVersionRollbackWorkflowDetailsWorkflowStepsSteps)
 *                         .build())
 *                     .type(runbookVersionRollbackWorkflowDetailsWorkflowType)
 *                     .build())
 *                 .build())
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * RunbookVersions can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:FleetAppsManagement/runbookVersion:RunbookVersion test_runbook_version &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:FleetAppsManagement/runbookVersion:RunbookVersion")
public class RunbookVersion extends com.pulumi.resources.CustomResource {
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example:
     * `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example:
     * `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Execution Workflow details.
     * 
     */
    @Export(name="executionWorkflowDetails", refs={RunbookVersionExecutionWorkflowDetails.class}, tree="[0]")
    private Output<RunbookVersionExecutionWorkflowDetails> executionWorkflowDetails;

    /**
     * @return (Updatable) Execution Workflow details.
     * 
     */
    public Output<RunbookVersionExecutionWorkflowDetails> executionWorkflowDetails() {
        return this.executionWorkflowDetails;
    }
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists
     * for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists
     * for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) The groups of the runbook.
     * 
     */
    @Export(name="groups", refs={List.class,RunbookVersionGroup.class}, tree="[0,1]")
    private Output<List<RunbookVersionGroup>> groups;

    /**
     * @return (Updatable) The groups of the runbook.
     * 
     */
    public Output<List<RunbookVersionGroup>> groups() {
        return this.groups;
    }
    @Export(name="isLatest", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isLatest;

    public Output<Boolean> isLatest() {
        return this.isLatest;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide
     * actionable information for a resource in Failed state.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide
     * actionable information for a resource in Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The name of the task
     * 
     */
    @Export(name="name", refs={String.class}, tree="[0]")
    private Output<String> name;

    /**
     * @return The name of the task
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * (Updatable) Rollback Workflow details.
     * 
     */
    @Export(name="rollbackWorkflowDetails", refs={RunbookVersionRollbackWorkflowDetails.class}, tree="[0]")
    private Output<RunbookVersionRollbackWorkflowDetails> rollbackWorkflowDetails;

    /**
     * @return (Updatable) Rollback Workflow details.
     * 
     */
    public Output<RunbookVersionRollbackWorkflowDetails> rollbackWorkflowDetails() {
        return this.rollbackWorkflowDetails;
    }
    /**
     * The OCID of the resource.
     * 
     */
    @Export(name="runbookId", refs={String.class}, tree="[0]")
    private Output<String> runbookId;

    /**
     * @return The OCID of the resource.
     * 
     */
    public Output<String> runbookId() {
        return this.runbookId;
    }
    /**
     * The current state of the FleetResource.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the FleetResource.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example:
     * `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example:
     * `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * (Updatable) A set of tasks to execute in the runbook.
     * 
     */
    @Export(name="tasks", refs={List.class,RunbookVersionTask.class}, tree="[0,1]")
    private Output<List<RunbookVersionTask>> tasks;

    /**
     * @return (Updatable) A set of tasks to execute in the runbook.
     * 
     */
    public Output<List<RunbookVersionTask>> tasks() {
        return this.tasks;
    }
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public RunbookVersion(java.lang.String name) {
        this(name, RunbookVersionArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public RunbookVersion(java.lang.String name, RunbookVersionArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public RunbookVersion(java.lang.String name, RunbookVersionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:FleetAppsManagement/runbookVersion:RunbookVersion", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private RunbookVersion(java.lang.String name, Output<java.lang.String> id, @Nullable RunbookVersionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:FleetAppsManagement/runbookVersion:RunbookVersion", name, state, makeResourceOptions(options, id), false);
    }

    private static RunbookVersionArgs makeArgs(RunbookVersionArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? RunbookVersionArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static RunbookVersion get(java.lang.String name, Output<java.lang.String> id, @Nullable RunbookVersionState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new RunbookVersion(name, id, state, options);
    }
}
