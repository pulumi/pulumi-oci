// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Streaming;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class StreamArgs extends com.pulumi.resources.ResourceArgs {

    public static final StreamArgs Empty = new StreamArgs();

    /**
     * (Updatable) The OCID of the compartment that contains the stream.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment that contains the stream.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The name of the stream. Avoid entering confidential information.  Example: `TelemetryEvents`
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return The name of the stream. Avoid entering confidential information.  Example: `TelemetryEvents`
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The number of partitions in the stream.
     * 
     */
    @Import(name="partitions", required=true)
    private Output<Integer> partitions;

    /**
     * @return The number of partitions in the stream.
     * 
     */
    public Output<Integer> partitions() {
        return this.partitions;
    }

    /**
     * The retention period of the stream, in hours. Accepted values are between 24 and 168 (7 days). If not specified, the stream will have a retention period of 24 hours.
     * 
     */
    @Import(name="retentionInHours")
    private @Nullable Output<Integer> retentionInHours;

    /**
     * @return The retention period of the stream, in hours. Accepted values are between 24 and 168 (7 days). If not specified, the stream will have a retention period of 24 hours.
     * 
     */
    public Optional<Output<Integer>> retentionInHours() {
        return Optional.ofNullable(this.retentionInHours);
    }

    /**
     * (Updatable) The OCID of the stream pool that contains the stream.
     * 
     */
    @Import(name="streamPoolId")
    private @Nullable Output<String> streamPoolId;

    /**
     * @return (Updatable) The OCID of the stream pool that contains the stream.
     * 
     */
    public Optional<Output<String>> streamPoolId() {
        return Optional.ofNullable(this.streamPoolId);
    }

    private StreamArgs() {}

    private StreamArgs(StreamArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.freeformTags = $.freeformTags;
        this.name = $.name;
        this.partitions = $.partitions;
        this.retentionInHours = $.retentionInHours;
        this.streamPoolId = $.streamPoolId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(StreamArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private StreamArgs $;

        public Builder() {
            $ = new StreamArgs();
        }

        public Builder(StreamArgs defaults) {
            $ = new StreamArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment that contains the stream.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment that contains the stream.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param name The name of the stream. Avoid entering confidential information.  Example: `TelemetryEvents`
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The name of the stream. Avoid entering confidential information.  Example: `TelemetryEvents`
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param partitions The number of partitions in the stream.
         * 
         * @return builder
         * 
         */
        public Builder partitions(Output<Integer> partitions) {
            $.partitions = partitions;
            return this;
        }

        /**
         * @param partitions The number of partitions in the stream.
         * 
         * @return builder
         * 
         */
        public Builder partitions(Integer partitions) {
            return partitions(Output.of(partitions));
        }

        /**
         * @param retentionInHours The retention period of the stream, in hours. Accepted values are between 24 and 168 (7 days). If not specified, the stream will have a retention period of 24 hours.
         * 
         * @return builder
         * 
         */
        public Builder retentionInHours(@Nullable Output<Integer> retentionInHours) {
            $.retentionInHours = retentionInHours;
            return this;
        }

        /**
         * @param retentionInHours The retention period of the stream, in hours. Accepted values are between 24 and 168 (7 days). If not specified, the stream will have a retention period of 24 hours.
         * 
         * @return builder
         * 
         */
        public Builder retentionInHours(Integer retentionInHours) {
            return retentionInHours(Output.of(retentionInHours));
        }

        /**
         * @param streamPoolId (Updatable) The OCID of the stream pool that contains the stream.
         * 
         * @return builder
         * 
         */
        public Builder streamPoolId(@Nullable Output<String> streamPoolId) {
            $.streamPoolId = streamPoolId;
            return this;
        }

        /**
         * @param streamPoolId (Updatable) The OCID of the stream pool that contains the stream.
         * 
         * @return builder
         * 
         */
        public Builder streamPoolId(String streamPoolId) {
            return streamPoolId(Output.of(streamPoolId));
        }

        public StreamArgs build() {
            $.partitions = Objects.requireNonNull($.partitions, "expected parameter 'partitions' to be non-null");
            return $;
        }
    }

}