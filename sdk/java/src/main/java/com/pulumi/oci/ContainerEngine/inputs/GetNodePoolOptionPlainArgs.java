// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetNodePoolOptionPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNodePoolOptionPlainArgs Empty = new GetNodePoolOptionPlainArgs();

    /**
     * The OCID of the compartment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable String compartmentId;

    /**
     * @return The OCID of the compartment.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The id of the option set to retrieve. Use &#34;all&#34; get all options, or use a cluster ID to get options specific to the provided cluster.
     * 
     */
    @Import(name="nodePoolOptionId", required=true)
    private String nodePoolOptionId;

    /**
     * @return The id of the option set to retrieve. Use &#34;all&#34; get all options, or use a cluster ID to get options specific to the provided cluster.
     * 
     */
    public String nodePoolOptionId() {
        return this.nodePoolOptionId;
    }

    private GetNodePoolOptionPlainArgs() {}

    private GetNodePoolOptionPlainArgs(GetNodePoolOptionPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.nodePoolOptionId = $.nodePoolOptionId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNodePoolOptionPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNodePoolOptionPlainArgs $;

        public Builder() {
            $ = new GetNodePoolOptionPlainArgs();
        }

        public Builder(GetNodePoolOptionPlainArgs defaults) {
            $ = new GetNodePoolOptionPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param nodePoolOptionId The id of the option set to retrieve. Use &#34;all&#34; get all options, or use a cluster ID to get options specific to the provided cluster.
         * 
         * @return builder
         * 
         */
        public Builder nodePoolOptionId(String nodePoolOptionId) {
            $.nodePoolOptionId = nodePoolOptionId;
            return this;
        }

        public GetNodePoolOptionPlainArgs build() {
            if ($.nodePoolOptionId == null) {
                throw new MissingRequiredPropertyException("GetNodePoolOptionPlainArgs", "nodePoolOptionId");
            }
            return $;
        }
    }

}
