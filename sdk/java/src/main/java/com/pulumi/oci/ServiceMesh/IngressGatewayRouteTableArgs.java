// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ServiceMesh.inputs.IngressGatewayRouteTableRouteRuleArgs;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class IngressGatewayRouteTableArgs extends com.pulumi.resources.ResourceArgs {

    public static final IngressGatewayRouteTableArgs Empty = new IngressGatewayRouteTableArgs();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The OCID of the service mesh in which this access policy is created.
     * 
     */
    @Import(name="ingressGatewayId", required=true)
    private Output<String> ingressGatewayId;

    /**
     * @return The OCID of the service mesh in which this access policy is created.
     * 
     */
    public Output<String> ingressGatewayId() {
        return this.ingressGatewayId;
    }

    /**
     * (Updatable) Name of the ingress gateway host that this route should apply to.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) Name of the ingress gateway host that this route should apply to.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) The priority of the route table. Lower value means higher priority. The routes are declared based on the priority.
     * 
     */
    @Import(name="priority")
    private @Nullable Output<Integer> priority;

    /**
     * @return (Updatable) The priority of the route table. Lower value means higher priority. The routes are declared based on the priority.
     * 
     */
    public Optional<Output<Integer>> priority() {
        return Optional.ofNullable(this.priority);
    }

    /**
     * (Updatable) The route rules for the ingress gateway.
     * 
     */
    @Import(name="routeRules", required=true)
    private Output<List<IngressGatewayRouteTableRouteRuleArgs>> routeRules;

    /**
     * @return (Updatable) The route rules for the ingress gateway.
     * 
     */
    public Output<List<IngressGatewayRouteTableRouteRuleArgs>> routeRules() {
        return this.routeRules;
    }

    private IngressGatewayRouteTableArgs() {}

    private IngressGatewayRouteTableArgs(IngressGatewayRouteTableArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.freeformTags = $.freeformTags;
        this.ingressGatewayId = $.ingressGatewayId;
        this.name = $.name;
        this.priority = $.priority;
        this.routeRules = $.routeRules;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(IngressGatewayRouteTableArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private IngressGatewayRouteTableArgs $;

        public Builder() {
            $ = new IngressGatewayRouteTableArgs();
        }

        public Builder(IngressGatewayRouteTableArgs defaults) {
            $ = new IngressGatewayRouteTableArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param ingressGatewayId The OCID of the service mesh in which this access policy is created.
         * 
         * @return builder
         * 
         */
        public Builder ingressGatewayId(Output<String> ingressGatewayId) {
            $.ingressGatewayId = ingressGatewayId;
            return this;
        }

        /**
         * @param ingressGatewayId The OCID of the service mesh in which this access policy is created.
         * 
         * @return builder
         * 
         */
        public Builder ingressGatewayId(String ingressGatewayId) {
            return ingressGatewayId(Output.of(ingressGatewayId));
        }

        /**
         * @param name (Updatable) Name of the ingress gateway host that this route should apply to.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) Name of the ingress gateway host that this route should apply to.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param priority (Updatable) The priority of the route table. Lower value means higher priority. The routes are declared based on the priority.
         * 
         * @return builder
         * 
         */
        public Builder priority(@Nullable Output<Integer> priority) {
            $.priority = priority;
            return this;
        }

        /**
         * @param priority (Updatable) The priority of the route table. Lower value means higher priority. The routes are declared based on the priority.
         * 
         * @return builder
         * 
         */
        public Builder priority(Integer priority) {
            return priority(Output.of(priority));
        }

        /**
         * @param routeRules (Updatable) The route rules for the ingress gateway.
         * 
         * @return builder
         * 
         */
        public Builder routeRules(Output<List<IngressGatewayRouteTableRouteRuleArgs>> routeRules) {
            $.routeRules = routeRules;
            return this;
        }

        /**
         * @param routeRules (Updatable) The route rules for the ingress gateway.
         * 
         * @return builder
         * 
         */
        public Builder routeRules(List<IngressGatewayRouteTableRouteRuleArgs> routeRules) {
            return routeRules(Output.of(routeRules));
        }

        /**
         * @param routeRules (Updatable) The route rules for the ingress gateway.
         * 
         * @return builder
         * 
         */
        public Builder routeRules(IngressGatewayRouteTableRouteRuleArgs... routeRules) {
            return routeRules(List.of(routeRules));
        }

        public IngressGatewayRouteTableArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.ingressGatewayId = Objects.requireNonNull($.ingressGatewayId, "expected parameter 'ingressGatewayId' to be non-null");
            $.routeRules = Objects.requireNonNull($.routeRules, "expected parameter 'routeRules' to be non-null");
            return $;
        }
    }

}