// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenericArtifactsContent.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetGenericArtifactsContentPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetGenericArtifactsContentPlainArgs Empty = new GetGenericArtifactsContentPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the artifact.  Example: `ocid1.genericartifact.oc1..exampleuniqueID`
     * 
     */
    @Import(name="artifactId", required=true)
    private String artifactId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the artifact.  Example: `ocid1.genericartifact.oc1..exampleuniqueID`
     * 
     */
    public String artifactId() {
        return this.artifactId;
    }

    private GetGenericArtifactsContentPlainArgs() {}

    private GetGenericArtifactsContentPlainArgs(GetGenericArtifactsContentPlainArgs $) {
        this.artifactId = $.artifactId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetGenericArtifactsContentPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetGenericArtifactsContentPlainArgs $;

        public Builder() {
            $ = new GetGenericArtifactsContentPlainArgs();
        }

        public Builder(GetGenericArtifactsContentPlainArgs defaults) {
            $ = new GetGenericArtifactsContentPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param artifactId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the artifact.  Example: `ocid1.genericartifact.oc1..exampleuniqueID`
         * 
         * @return builder
         * 
         */
        public Builder artifactId(String artifactId) {
            $.artifactId = artifactId;
            return this;
        }

        public GetGenericArtifactsContentPlainArgs build() {
            if ($.artifactId == null) {
                throw new MissingRequiredPropertyException("GetGenericArtifactsContentPlainArgs", "artifactId");
            }
            return $;
        }
    }

}
