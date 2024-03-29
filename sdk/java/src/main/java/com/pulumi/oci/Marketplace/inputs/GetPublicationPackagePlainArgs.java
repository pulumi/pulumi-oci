// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetPublicationPackagePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetPublicationPackagePlainArgs Empty = new GetPublicationPackagePlainArgs();

    /**
     * The version of the package. Package versions are unique within a listing.
     * 
     */
    @Import(name="packageVersion", required=true)
    private String packageVersion;

    /**
     * @return The version of the package. Package versions are unique within a listing.
     * 
     */
    public String packageVersion() {
        return this.packageVersion;
    }

    /**
     * The unique identifier for the publication.
     * 
     */
    @Import(name="publicationId", required=true)
    private String publicationId;

    /**
     * @return The unique identifier for the publication.
     * 
     */
    public String publicationId() {
        return this.publicationId;
    }

    private GetPublicationPackagePlainArgs() {}

    private GetPublicationPackagePlainArgs(GetPublicationPackagePlainArgs $) {
        this.packageVersion = $.packageVersion;
        this.publicationId = $.publicationId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetPublicationPackagePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPublicationPackagePlainArgs $;

        public Builder() {
            $ = new GetPublicationPackagePlainArgs();
        }

        public Builder(GetPublicationPackagePlainArgs defaults) {
            $ = new GetPublicationPackagePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param packageVersion The version of the package. Package versions are unique within a listing.
         * 
         * @return builder
         * 
         */
        public Builder packageVersion(String packageVersion) {
            $.packageVersion = packageVersion;
            return this;
        }

        /**
         * @param publicationId The unique identifier for the publication.
         * 
         * @return builder
         * 
         */
        public Builder publicationId(String publicationId) {
            $.publicationId = publicationId;
            return this;
        }

        public GetPublicationPackagePlainArgs build() {
            if ($.packageVersion == null) {
                throw new MissingRequiredPropertyException("GetPublicationPackagePlainArgs", "packageVersion");
            }
            if ($.publicationId == null) {
                throw new MissingRequiredPropertyException("GetPublicationPackagePlainArgs", "publicationId");
            }
            return $;
        }
    }

}
