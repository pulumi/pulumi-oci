// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Artifacts.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetContainerImagePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetContainerImagePlainArgs Empty = new GetContainerImagePlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image.  Example: `ocid1.containerimage.oc1..exampleuniqueID`
     * 
     */
    @Import(name="imageId", required=true)
    private String imageId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image.  Example: `ocid1.containerimage.oc1..exampleuniqueID`
     * 
     */
    public String imageId() {
        return this.imageId;
    }

    private GetContainerImagePlainArgs() {}

    private GetContainerImagePlainArgs(GetContainerImagePlainArgs $) {
        this.imageId = $.imageId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetContainerImagePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetContainerImagePlainArgs $;

        public Builder() {
            $ = new GetContainerImagePlainArgs();
        }

        public Builder(GetContainerImagePlainArgs defaults) {
            $ = new GetContainerImagePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param imageId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image.  Example: `ocid1.containerimage.oc1..exampleuniqueID`
         * 
         * @return builder
         * 
         */
        public Builder imageId(String imageId) {
            $.imageId = imageId;
            return this;
        }

        public GetContainerImagePlainArgs build() {
            if ($.imageId == null) {
                throw new MissingRequiredPropertyException("GetContainerImagePlainArgs", "imageId");
            }
            return $;
        }
    }

}
