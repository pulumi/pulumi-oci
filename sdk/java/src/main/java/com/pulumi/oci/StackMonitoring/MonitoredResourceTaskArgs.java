// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.StackMonitoring.inputs.MonitoredResourceTaskTaskDetailsArgs;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MonitoredResourceTaskArgs extends com.pulumi.resources.ResourceArgs {

    public static final MonitoredResourceTaskArgs Empty = new MonitoredResourceTaskArgs();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment identifier.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment identifier.
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
     * Name of the task. If not provided by default the following names will be taken Oracle Cloud Infrastructure tasks - namespace plus timestamp.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Name of the task. If not provided by default the following names will be taken Oracle Cloud Infrastructure tasks - namespace plus timestamp.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The request details for the performing the task.
     * 
     */
    @Import(name="taskDetails", required=true)
    private Output<MonitoredResourceTaskTaskDetailsArgs> taskDetails;

    /**
     * @return The request details for the performing the task.
     * 
     */
    public Output<MonitoredResourceTaskTaskDetailsArgs> taskDetails() {
        return this.taskDetails;
    }

    private MonitoredResourceTaskArgs() {}

    private MonitoredResourceTaskArgs(MonitoredResourceTaskArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.freeformTags = $.freeformTags;
        this.name = $.name;
        this.taskDetails = $.taskDetails;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MonitoredResourceTaskArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MonitoredResourceTaskArgs $;

        public Builder() {
            $ = new MonitoredResourceTaskArgs();
        }

        public Builder(MonitoredResourceTaskArgs defaults) {
            $ = new MonitoredResourceTaskArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment identifier.
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
         * @param name Name of the task. If not provided by default the following names will be taken Oracle Cloud Infrastructure tasks - namespace plus timestamp.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Name of the task. If not provided by default the following names will be taken Oracle Cloud Infrastructure tasks - namespace plus timestamp.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param taskDetails The request details for the performing the task.
         * 
         * @return builder
         * 
         */
        public Builder taskDetails(Output<MonitoredResourceTaskTaskDetailsArgs> taskDetails) {
            $.taskDetails = taskDetails;
            return this;
        }

        /**
         * @param taskDetails The request details for the performing the task.
         * 
         * @return builder
         * 
         */
        public Builder taskDetails(MonitoredResourceTaskTaskDetailsArgs taskDetails) {
            return taskDetails(Output.of(taskDetails));
        }

        public MonitoredResourceTaskArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.taskDetails = Objects.requireNonNull($.taskDetails, "expected parameter 'taskDetails' to be non-null");
            return $;
        }
    }

}