// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDomainsMySupportAccountPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDomainsMySupportAccountPlainArgs Empty = new GetDomainsMySupportAccountPlainArgs();

    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    @Import(name="authorization")
    private @Nullable String authorization;

    /**
     * @return The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    public Optional<String> authorization() {
        return Optional.ofNullable(this.authorization);
    }

    /**
     * The basic endpoint for the identity domain
     * 
     */
    @Import(name="idcsEndpoint", required=true)
    private String idcsEndpoint;

    /**
     * @return The basic endpoint for the identity domain
     * 
     */
    public String idcsEndpoint() {
        return this.idcsEndpoint;
    }

    /**
     * ID of the resource
     * 
     */
    @Import(name="mySupportAccountId", required=true)
    private String mySupportAccountId;

    /**
     * @return ID of the resource
     * 
     */
    public String mySupportAccountId() {
        return this.mySupportAccountId;
    }

    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    @Import(name="resourceTypeSchemaVersion")
    private @Nullable String resourceTypeSchemaVersion;

    /**
     * @return An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    public Optional<String> resourceTypeSchemaVersion() {
        return Optional.ofNullable(this.resourceTypeSchemaVersion);
    }

    private GetDomainsMySupportAccountPlainArgs() {}

    private GetDomainsMySupportAccountPlainArgs(GetDomainsMySupportAccountPlainArgs $) {
        this.authorization = $.authorization;
        this.idcsEndpoint = $.idcsEndpoint;
        this.mySupportAccountId = $.mySupportAccountId;
        this.resourceTypeSchemaVersion = $.resourceTypeSchemaVersion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDomainsMySupportAccountPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDomainsMySupportAccountPlainArgs $;

        public Builder() {
            $ = new GetDomainsMySupportAccountPlainArgs();
        }

        public Builder(GetDomainsMySupportAccountPlainArgs defaults) {
            $ = new GetDomainsMySupportAccountPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param authorization The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
         * 
         * @return builder
         * 
         */
        public Builder authorization(@Nullable String authorization) {
            $.authorization = authorization;
            return this;
        }

        /**
         * @param idcsEndpoint The basic endpoint for the identity domain
         * 
         * @return builder
         * 
         */
        public Builder idcsEndpoint(String idcsEndpoint) {
            $.idcsEndpoint = idcsEndpoint;
            return this;
        }

        /**
         * @param mySupportAccountId ID of the resource
         * 
         * @return builder
         * 
         */
        public Builder mySupportAccountId(String mySupportAccountId) {
            $.mySupportAccountId = mySupportAccountId;
            return this;
        }

        /**
         * @param resourceTypeSchemaVersion An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
         * 
         * @return builder
         * 
         */
        public Builder resourceTypeSchemaVersion(@Nullable String resourceTypeSchemaVersion) {
            $.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            return this;
        }

        public GetDomainsMySupportAccountPlainArgs build() {
            if ($.idcsEndpoint == null) {
                throw new MissingRequiredPropertyException("GetDomainsMySupportAccountPlainArgs", "idcsEndpoint");
            }
            if ($.mySupportAccountId == null) {
                throw new MissingRequiredPropertyException("GetDomainsMySupportAccountPlainArgs", "mySupportAccountId");
            }
            return $;
        }
    }

}
