// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDomainsMyUserDbCredentialArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDomainsMyUserDbCredentialArgs Empty = new GetDomainsMyUserDbCredentialArgs();

    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    @Import(name="authorization")
    private @Nullable Output<String> authorization;

    /**
     * @return The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    public Optional<Output<String>> authorization() {
        return Optional.ofNullable(this.authorization);
    }

    /**
     * The basic endpoint for the identity domain
     * 
     */
    @Import(name="idcsEndpoint", required=true)
    private Output<String> idcsEndpoint;

    /**
     * @return The basic endpoint for the identity domain
     * 
     */
    public Output<String> idcsEndpoint() {
        return this.idcsEndpoint;
    }

    /**
     * ID of the resource
     * 
     */
    @Import(name="myUserDbCredentialId", required=true)
    private Output<String> myUserDbCredentialId;

    /**
     * @return ID of the resource
     * 
     */
    public Output<String> myUserDbCredentialId() {
        return this.myUserDbCredentialId;
    }

    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    @Import(name="resourceTypeSchemaVersion")
    private @Nullable Output<String> resourceTypeSchemaVersion;

    /**
     * @return An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    public Optional<Output<String>> resourceTypeSchemaVersion() {
        return Optional.ofNullable(this.resourceTypeSchemaVersion);
    }

    private GetDomainsMyUserDbCredentialArgs() {}

    private GetDomainsMyUserDbCredentialArgs(GetDomainsMyUserDbCredentialArgs $) {
        this.authorization = $.authorization;
        this.idcsEndpoint = $.idcsEndpoint;
        this.myUserDbCredentialId = $.myUserDbCredentialId;
        this.resourceTypeSchemaVersion = $.resourceTypeSchemaVersion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDomainsMyUserDbCredentialArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDomainsMyUserDbCredentialArgs $;

        public Builder() {
            $ = new GetDomainsMyUserDbCredentialArgs();
        }

        public Builder(GetDomainsMyUserDbCredentialArgs defaults) {
            $ = new GetDomainsMyUserDbCredentialArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param authorization The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
         * 
         * @return builder
         * 
         */
        public Builder authorization(@Nullable Output<String> authorization) {
            $.authorization = authorization;
            return this;
        }

        /**
         * @param authorization The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
         * 
         * @return builder
         * 
         */
        public Builder authorization(String authorization) {
            return authorization(Output.of(authorization));
        }

        /**
         * @param idcsEndpoint The basic endpoint for the identity domain
         * 
         * @return builder
         * 
         */
        public Builder idcsEndpoint(Output<String> idcsEndpoint) {
            $.idcsEndpoint = idcsEndpoint;
            return this;
        }

        /**
         * @param idcsEndpoint The basic endpoint for the identity domain
         * 
         * @return builder
         * 
         */
        public Builder idcsEndpoint(String idcsEndpoint) {
            return idcsEndpoint(Output.of(idcsEndpoint));
        }

        /**
         * @param myUserDbCredentialId ID of the resource
         * 
         * @return builder
         * 
         */
        public Builder myUserDbCredentialId(Output<String> myUserDbCredentialId) {
            $.myUserDbCredentialId = myUserDbCredentialId;
            return this;
        }

        /**
         * @param myUserDbCredentialId ID of the resource
         * 
         * @return builder
         * 
         */
        public Builder myUserDbCredentialId(String myUserDbCredentialId) {
            return myUserDbCredentialId(Output.of(myUserDbCredentialId));
        }

        /**
         * @param resourceTypeSchemaVersion An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
         * 
         * @return builder
         * 
         */
        public Builder resourceTypeSchemaVersion(@Nullable Output<String> resourceTypeSchemaVersion) {
            $.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            return this;
        }

        /**
         * @param resourceTypeSchemaVersion An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
         * 
         * @return builder
         * 
         */
        public Builder resourceTypeSchemaVersion(String resourceTypeSchemaVersion) {
            return resourceTypeSchemaVersion(Output.of(resourceTypeSchemaVersion));
        }

        public GetDomainsMyUserDbCredentialArgs build() {
            if ($.idcsEndpoint == null) {
                throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialArgs", "idcsEndpoint");
            }
            if ($.myUserDbCredentialId == null) {
                throw new MissingRequiredPropertyException("GetDomainsMyUserDbCredentialArgs", "myUserDbCredentialId");
            }
            return $;
        }
    }

}
