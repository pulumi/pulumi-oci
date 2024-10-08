// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetTagArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetTagArgs Empty = new GetTagArgs();

    /**
     * The name of the tag.
     * 
     */
    @Import(name="tagName", required=true)
    private Output<String> tagName;

    /**
     * @return The name of the tag.
     * 
     */
    public Output<String> tagName() {
        return this.tagName;
    }

    /**
     * The OCID of the tag namespace.
     * 
     */
    @Import(name="tagNamespaceId", required=true)
    private Output<String> tagNamespaceId;

    /**
     * @return The OCID of the tag namespace.
     * 
     */
    public Output<String> tagNamespaceId() {
        return this.tagNamespaceId;
    }

    private GetTagArgs() {}

    private GetTagArgs(GetTagArgs $) {
        this.tagName = $.tagName;
        this.tagNamespaceId = $.tagNamespaceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetTagArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetTagArgs $;

        public Builder() {
            $ = new GetTagArgs();
        }

        public Builder(GetTagArgs defaults) {
            $ = new GetTagArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param tagName The name of the tag.
         * 
         * @return builder
         * 
         */
        public Builder tagName(Output<String> tagName) {
            $.tagName = tagName;
            return this;
        }

        /**
         * @param tagName The name of the tag.
         * 
         * @return builder
         * 
         */
        public Builder tagName(String tagName) {
            return tagName(Output.of(tagName));
        }

        /**
         * @param tagNamespaceId The OCID of the tag namespace.
         * 
         * @return builder
         * 
         */
        public Builder tagNamespaceId(Output<String> tagNamespaceId) {
            $.tagNamespaceId = tagNamespaceId;
            return this;
        }

        /**
         * @param tagNamespaceId The OCID of the tag namespace.
         * 
         * @return builder
         * 
         */
        public Builder tagNamespaceId(String tagNamespaceId) {
            return tagNamespaceId(Output.of(tagNamespaceId));
        }

        public GetTagArgs build() {
            if ($.tagName == null) {
                throw new MissingRequiredPropertyException("GetTagArgs", "tagName");
            }
            if ($.tagNamespaceId == null) {
                throw new MissingRequiredPropertyException("GetTagArgs", "tagNamespaceId");
            }
            return $;
        }
    }

}
