// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ManagementAgent;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.ManagementAgent.ManagementAgentInstallKeyArgs;
import com.pulumi.oci.ManagementAgent.inputs.ManagementAgentInstallKeyState;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Management Agent Install Key resource in Oracle Cloud Infrastructure Management Agent service.
 * 
 * User creates a new install key as part of this API.
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * ManagementAgentInstallKeys can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:ManagementAgent/managementAgentInstallKey:ManagementAgentInstallKey test_management_agent_install_key &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:ManagementAgent/managementAgentInstallKey:ManagementAgentInstallKey")
public class ManagementAgentInstallKey extends com.pulumi.resources.CustomResource {
    /**
     * Total number of install for this keys
     * 
     */
    @Export(name="allowedKeyInstallCount", type=Integer.class, parameters={})
    private Output<Integer> allowedKeyInstallCount;

    /**
     * @return Total number of install for this keys
     * 
     */
    public Output<Integer> allowedKeyInstallCount() {
        return this.allowedKeyInstallCount;
    }
    /**
     * Compartment Identifier
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return Compartment Identifier
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * Principal id of user who created the Agent Install key
     * 
     */
    @Export(name="createdByPrincipalId", type=String.class, parameters={})
    private Output<String> createdByPrincipalId;

    /**
     * @return Principal id of user who created the Agent Install key
     * 
     */
    public Output<String> createdByPrincipalId() {
        return this.createdByPrincipalId;
    }
    /**
     * Total number of install for this keys
     * 
     */
    @Export(name="currentKeyInstallCount", type=Integer.class, parameters={})
    private Output<Integer> currentKeyInstallCount;

    /**
     * @return Total number of install for this keys
     * 
     */
    public Output<Integer> currentKeyInstallCount() {
        return this.currentKeyInstallCount;
    }
    /**
     * (Updatable) Management Agent install Key Name
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) Management Agent install Key Name
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * If set to true, the install key has no expiration date or usage limit. Defaults to false
     * 
     */
    @Export(name="isUnlimited", type=Boolean.class, parameters={})
    private Output<Boolean> isUnlimited;

    /**
     * @return If set to true, the install key has no expiration date or usage limit. Defaults to false
     * 
     */
    public Output<Boolean> isUnlimited() {
        return this.isUnlimited;
    }
    /**
     * Management Agent Install Key
     * 
     */
    @Export(name="key", type=String.class, parameters={})
    private Output<String> key;

    /**
     * @return Management Agent Install Key
     * 
     */
    public Output<String> key() {
        return this.key;
    }
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * Status of Key
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return Status of Key
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The time when Management Agent install Key was created. An RFC3339 formatted date time string
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The time when Management Agent install Key was created. An RFC3339 formatted date time string
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * date after which key would expire after creation
     * 
     */
    @Export(name="timeExpires", type=String.class, parameters={})
    private Output<String> timeExpires;

    /**
     * @return date after which key would expire after creation
     * 
     */
    public Output<String> timeExpires() {
        return this.timeExpires;
    }
    /**
     * The time when Management Agent install Key was updated. An RFC3339 formatted date time string
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return The time when Management Agent install Key was updated. An RFC3339 formatted date time string
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ManagementAgentInstallKey(String name) {
        this(name, ManagementAgentInstallKeyArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ManagementAgentInstallKey(String name, ManagementAgentInstallKeyArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ManagementAgentInstallKey(String name, ManagementAgentInstallKeyArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:ManagementAgent/managementAgentInstallKey:ManagementAgentInstallKey", name, args == null ? ManagementAgentInstallKeyArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private ManagementAgentInstallKey(String name, Output<String> id, @Nullable ManagementAgentInstallKeyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:ManagementAgent/managementAgentInstallKey:ManagementAgentInstallKey", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
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
    public static ManagementAgentInstallKey get(String name, Output<String> id, @Nullable ManagementAgentInstallKeyState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ManagementAgentInstallKey(name, id, state, options);
    }
}
