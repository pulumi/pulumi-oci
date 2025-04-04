// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.inputs.DomainsCustomerSecretKeyTagArgs;
import com.pulumi.oci.Identity.inputs.DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs;
import com.pulumi.oci.Identity.inputs.DomainsCustomerSecretKeyUserArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsCustomerSecretKeyArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsCustomerSecretKeyArgs Empty = new DomainsCustomerSecretKeyArgs();

    /**
     * A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If &#39;attributes&#39; query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
     * 
     */
    @Import(name="attributeSets")
    private @Nullable Output<List<String>> attributeSets;

    /**
     * @return A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If &#39;attributes&#39; query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
     * 
     */
    public Optional<Output<List<String>>> attributeSets() {
        return Optional.ofNullable(this.attributeSets);
    }

    /**
     * A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
     * 
     */
    @Import(name="attributes")
    private @Nullable Output<String> attributes;

    /**
     * @return A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
     * 
     */
    public Optional<Output<String>> attributes() {
        return Optional.ofNullable(this.attributes);
    }

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
     * Description
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * type: string
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return Description
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * type: string
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * Display Name
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * type: string
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return Display Name
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * type: string
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * When the user&#39;s credential expire.
     * 
     * **Added In:** 2109090424
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: dateTime
     * * uniqueness: none
     * 
     */
    @Import(name="expiresOn")
    private @Nullable Output<String> expiresOn;

    /**
     * @return When the user&#39;s credential expire.
     * 
     * **Added In:** 2109090424
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: dateTime
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> expiresOn() {
        return Optional.ofNullable(this.expiresOn);
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
     * Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: global
     * 
     */
    @Import(name="ocid")
    private @Nullable Output<String> ocid;

    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: global
     * 
     */
    public Optional<Output<String>> ocid() {
        return Optional.ofNullable(this.ocid);
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

    /**
     * REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: true
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="schemas", required=true)
    private Output<List<String>> schemas;

    /**
     * @return REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: true
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<List<String>> schemas() {
        return this.schemas;
    }

    /**
     * The user&#39;s credential status.
     * 
     * **Added In:** 2109090424
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: never
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="status")
    private @Nullable Output<String> status;

    /**
     * @return The user&#39;s credential status.
     * 
     * **Added In:** 2109090424
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: never
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    /**
     * A list of tags on this resource.
     * 
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [key, value]
     * * idcsSearchable: true
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: complex
     * * uniqueness: none
     * 
     */
    @Import(name="tags")
    private @Nullable Output<List<DomainsCustomerSecretKeyTagArgs>> tags;

    /**
     * @return A list of tags on this resource.
     * 
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [key, value]
     * * idcsSearchable: true
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: complex
     * * uniqueness: none
     * 
     */
    public Optional<Output<List<DomainsCustomerSecretKeyTagArgs>>> tags() {
        return Optional.ofNullable(this.tags);
    }

    /**
     * Controls whether a user can update themselves or not via User related APIs
     * 
     */
    @Import(name="urnietfparamsscimschemasoracleidcsextensionselfChangeUser")
    private @Nullable Output<DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs> urnietfparamsscimschemasoracleidcsextensionselfChangeUser;

    /**
     * @return Controls whether a user can update themselves or not via User related APIs
     * 
     */
    public Optional<Output<DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs>> urnietfparamsscimschemasoracleidcsextensionselfChangeUser() {
        return Optional.ofNullable(this.urnietfparamsscimschemasoracleidcsextensionselfChangeUser);
    }

    /**
     * User linked to customer secret key
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: complex
     * * uniqueness: none
     * 
     */
    @Import(name="user")
    private @Nullable Output<DomainsCustomerSecretKeyUserArgs> user;

    /**
     * @return User linked to customer secret key
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: complex
     * * uniqueness: none
     * 
     */
    public Optional<Output<DomainsCustomerSecretKeyUserArgs>> user() {
        return Optional.ofNullable(this.user);
    }

    private DomainsCustomerSecretKeyArgs() {}

    private DomainsCustomerSecretKeyArgs(DomainsCustomerSecretKeyArgs $) {
        this.attributeSets = $.attributeSets;
        this.attributes = $.attributes;
        this.authorization = $.authorization;
        this.description = $.description;
        this.displayName = $.displayName;
        this.expiresOn = $.expiresOn;
        this.idcsEndpoint = $.idcsEndpoint;
        this.ocid = $.ocid;
        this.resourceTypeSchemaVersion = $.resourceTypeSchemaVersion;
        this.schemas = $.schemas;
        this.status = $.status;
        this.tags = $.tags;
        this.urnietfparamsscimschemasoracleidcsextensionselfChangeUser = $.urnietfparamsscimschemasoracleidcsextensionselfChangeUser;
        this.user = $.user;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsCustomerSecretKeyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsCustomerSecretKeyArgs $;

        public Builder() {
            $ = new DomainsCustomerSecretKeyArgs();
        }

        public Builder(DomainsCustomerSecretKeyArgs defaults) {
            $ = new DomainsCustomerSecretKeyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param attributeSets A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If &#39;attributes&#39; query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder attributeSets(@Nullable Output<List<String>> attributeSets) {
            $.attributeSets = attributeSets;
            return this;
        }

        /**
         * @param attributeSets A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If &#39;attributes&#39; query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder attributeSets(List<String> attributeSets) {
            return attributeSets(Output.of(attributeSets));
        }

        /**
         * @param attributeSets A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If &#39;attributes&#39; query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder attributeSets(String... attributeSets) {
            return attributeSets(List.of(attributeSets));
        }

        /**
         * @param attributes A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
         * 
         * @return builder
         * 
         */
        public Builder attributes(@Nullable Output<String> attributes) {
            $.attributes = attributes;
            return this;
        }

        /**
         * @param attributes A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
         * 
         * @return builder
         * 
         */
        public Builder attributes(String attributes) {
            return attributes(Output.of(attributes));
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
         * @param description Description
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * type: string
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description Description
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * type: string
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName Display Name
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * type: string
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName Display Name
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * type: string
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param expiresOn When the user&#39;s credential expire.
         * 
         * **Added In:** 2109090424
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: immutable
         * * required: false
         * * returned: default
         * * type: dateTime
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder expiresOn(@Nullable Output<String> expiresOn) {
            $.expiresOn = expiresOn;
            return this;
        }

        /**
         * @param expiresOn When the user&#39;s credential expire.
         * 
         * **Added In:** 2109090424
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: immutable
         * * required: false
         * * returned: default
         * * type: dateTime
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder expiresOn(String expiresOn) {
            return expiresOn(Output.of(expiresOn));
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
         * @param ocid Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: immutable
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: global
         * 
         * @return builder
         * 
         */
        public Builder ocid(@Nullable Output<String> ocid) {
            $.ocid = ocid;
            return this;
        }

        /**
         * @param ocid Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: immutable
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: global
         * 
         * @return builder
         * 
         */
        public Builder ocid(String ocid) {
            return ocid(Output.of(ocid));
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

        /**
         * @param schemas REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: true
         * * mutability: readWrite
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder schemas(Output<List<String>> schemas) {
            $.schemas = schemas;
            return this;
        }

        /**
         * @param schemas REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: true
         * * mutability: readWrite
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder schemas(List<String> schemas) {
            return schemas(Output.of(schemas));
        }

        /**
         * @param schemas REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: true
         * * mutability: readWrite
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder schemas(String... schemas) {
            return schemas(List.of(schemas));
        }

        /**
         * @param status The user&#39;s credential status.
         * 
         * **Added In:** 2109090424
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: never
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        /**
         * @param status The user&#39;s credential status.
         * 
         * **Added In:** 2109090424
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: never
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder status(String status) {
            return status(Output.of(status));
        }

        /**
         * @param tags A list of tags on this resource.
         * 
         * **SCIM++ Properties:**
         * * idcsCompositeKey: [key, value]
         * * idcsSearchable: true
         * * multiValued: true
         * * mutability: readWrite
         * * required: false
         * * returned: request
         * * type: complex
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder tags(@Nullable Output<List<DomainsCustomerSecretKeyTagArgs>> tags) {
            $.tags = tags;
            return this;
        }

        /**
         * @param tags A list of tags on this resource.
         * 
         * **SCIM++ Properties:**
         * * idcsCompositeKey: [key, value]
         * * idcsSearchable: true
         * * multiValued: true
         * * mutability: readWrite
         * * required: false
         * * returned: request
         * * type: complex
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder tags(List<DomainsCustomerSecretKeyTagArgs> tags) {
            return tags(Output.of(tags));
        }

        /**
         * @param tags A list of tags on this resource.
         * 
         * **SCIM++ Properties:**
         * * idcsCompositeKey: [key, value]
         * * idcsSearchable: true
         * * multiValued: true
         * * mutability: readWrite
         * * required: false
         * * returned: request
         * * type: complex
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder tags(DomainsCustomerSecretKeyTagArgs... tags) {
            return tags(List.of(tags));
        }

        /**
         * @param urnietfparamsscimschemasoracleidcsextensionselfChangeUser Controls whether a user can update themselves or not via User related APIs
         * 
         * @return builder
         * 
         */
        public Builder urnietfparamsscimschemasoracleidcsextensionselfChangeUser(@Nullable Output<DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs> urnietfparamsscimschemasoracleidcsextensionselfChangeUser) {
            $.urnietfparamsscimschemasoracleidcsextensionselfChangeUser = urnietfparamsscimschemasoracleidcsextensionselfChangeUser;
            return this;
        }

        /**
         * @param urnietfparamsscimschemasoracleidcsextensionselfChangeUser Controls whether a user can update themselves or not via User related APIs
         * 
         * @return builder
         * 
         */
        public Builder urnietfparamsscimschemasoracleidcsextensionselfChangeUser(DomainsCustomerSecretKeyUrnietfparamsscimschemasoracleidcsextensionselfChangeUserArgs urnietfparamsscimschemasoracleidcsextensionselfChangeUser) {
            return urnietfparamsscimschemasoracleidcsextensionselfChangeUser(Output.of(urnietfparamsscimschemasoracleidcsextensionselfChangeUser));
        }

        /**
         * @param user User linked to customer secret key
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: immutable
         * * required: false
         * * returned: default
         * * type: complex
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder user(@Nullable Output<DomainsCustomerSecretKeyUserArgs> user) {
            $.user = user;
            return this;
        }

        /**
         * @param user User linked to customer secret key
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: immutable
         * * required: false
         * * returned: default
         * * type: complex
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder user(DomainsCustomerSecretKeyUserArgs user) {
            return user(Output.of(user));
        }

        public DomainsCustomerSecretKeyArgs build() {
            if ($.idcsEndpoint == null) {
                throw new MissingRequiredPropertyException("DomainsCustomerSecretKeyArgs", "idcsEndpoint");
            }
            if ($.schemas == null) {
                throw new MissingRequiredPropertyException("DomainsCustomerSecretKeyArgs", "schemas");
            }
            return $;
        }
    }

}
