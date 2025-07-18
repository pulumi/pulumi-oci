// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.GenerativeAi.AgentAgentArgs;
import com.pulumi.oci.GenerativeAi.inputs.AgentAgentState;
import com.pulumi.oci.GenerativeAi.outputs.AgentAgentLlmConfig;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Agent resource in Oracle Cloud Infrastructure Generative Ai Agent service.
 * 
 * Creates an agent.
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
 * import com.pulumi.oci.GenerativeAi.AgentAgent;
 * import com.pulumi.oci.GenerativeAi.AgentAgentArgs;
 * import com.pulumi.oci.GenerativeAi.inputs.AgentAgentLlmConfigArgs;
 * import com.pulumi.oci.GenerativeAi.inputs.AgentAgentLlmConfigRoutingLlmCustomizationArgs;
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
 *         var testAgent = new AgentAgent("testAgent", AgentAgentArgs.builder()
 *             .compartmentId(compartmentId)
 *             .definedTags(Map.of("Operations.CostCenter", "42"))
 *             .description(agentDescription)
 *             .displayName(agentDisplayName)
 *             .freeformTags(Map.of("Department", "Finance"))
 *             .knowledgeBaseIds(agentKnowledgeBaseIds)
 *             .llmConfig(AgentAgentLlmConfigArgs.builder()
 *                 .routingLlmCustomization(AgentAgentLlmConfigRoutingLlmCustomizationArgs.builder()
 *                     .instruction(agentLlmConfigRoutingLlmCustomizationInstruction)
 *                     .build())
 *                 .build())
 *             .welcomeMessage(agentWelcomeMessage)
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
 * Agents can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:GenerativeAi/agentAgent:AgentAgent test_agent &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:GenerativeAi/agentAgent:AgentAgent")
public class AgentAgent extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the agent in.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the agent in.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Description about the agent.
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return (Updatable) Description about the agent.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) List of [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the knowledgeBases associated with agent. This field is deprecated and will be removed after March 26 2026.
     * 
     */
    @Export(name="knowledgeBaseIds", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> knowledgeBaseIds;

    /**
     * @return (Updatable) List of [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the knowledgeBases associated with agent. This field is deprecated and will be removed after March 26 2026.
     * 
     */
    public Output<List<String>> knowledgeBaseIds() {
        return this.knowledgeBaseIds;
    }
    /**
     * A message that describes the current state of the agent in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return A message that describes the current state of the agent in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * (Updatable) Configuration to Agent LLM.
     * 
     */
    @Export(name="llmConfig", refs={AgentAgentLlmConfig.class}, tree="[0]")
    private Output<AgentAgentLlmConfig> llmConfig;

    /**
     * @return (Updatable) Configuration to Agent LLM.
     * 
     */
    public Output<AgentAgentLlmConfig> llmConfig() {
        return this.llmConfig;
    }
    /**
     * The current state of the agent.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the agent.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The date and time the agent was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the agent was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the agent was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The date and time the agent was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * (Updatable) Details about purpose and responsibility of the agent
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="welcomeMessage", refs={String.class}, tree="[0]")
    private Output<String> welcomeMessage;

    /**
     * @return (Updatable) Details about purpose and responsibility of the agent
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> welcomeMessage() {
        return this.welcomeMessage;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public AgentAgent(java.lang.String name) {
        this(name, AgentAgentArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public AgentAgent(java.lang.String name, AgentAgentArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public AgentAgent(java.lang.String name, AgentAgentArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:GenerativeAi/agentAgent:AgentAgent", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private AgentAgent(java.lang.String name, Output<java.lang.String> id, @Nullable AgentAgentState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:GenerativeAi/agentAgent:AgentAgent", name, state, makeResourceOptions(options, id), false);
    }

    private static AgentAgentArgs makeArgs(AgentAgentArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? AgentAgentArgs.Empty : args;
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
    public static AgentAgent get(java.lang.String name, Output<java.lang.String> id, @Nullable AgentAgentState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new AgentAgent(name, id, state, options);
    }
}
