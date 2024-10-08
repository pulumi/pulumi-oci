// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetTagDefaultArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetTagDefaultArgs Empty = new GetTagDefaultArgs();

    /**
     * The OCID of the tag default.
     * 
     */
    @Import(name="tagDefaultId", required=true)
    private Output<String> tagDefaultId;

    /**
     * @return The OCID of the tag default.
     * 
     */
    public Output<String> tagDefaultId() {
        return this.tagDefaultId;
    }

    private GetTagDefaultArgs() {}

    private GetTagDefaultArgs(GetTagDefaultArgs $) {
        this.tagDefaultId = $.tagDefaultId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetTagDefaultArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetTagDefaultArgs $;

        public Builder() {
            $ = new GetTagDefaultArgs();
        }

        public Builder(GetTagDefaultArgs defaults) {
            $ = new GetTagDefaultArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param tagDefaultId The OCID of the tag default.
         * 
         * @return builder
         * 
         */
        public Builder tagDefaultId(Output<String> tagDefaultId) {
            $.tagDefaultId = tagDefaultId;
            return this;
        }

        /**
         * @param tagDefaultId The OCID of the tag default.
         * 
         * @return builder
         * 
         */
        public Builder tagDefaultId(String tagDefaultId) {
            return tagDefaultId(Output.of(tagDefaultId));
        }

        public GetTagDefaultArgs build() {
            if ($.tagDefaultId == null) {
                throw new MissingRequiredPropertyException("GetTagDefaultArgs", "tagDefaultId");
            }
            return $;
        }
    }

}
