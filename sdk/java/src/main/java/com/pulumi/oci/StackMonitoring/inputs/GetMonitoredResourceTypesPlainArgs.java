// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.StackMonitoring.inputs.GetMonitoredResourceTypesFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetMonitoredResourceTypesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMonitoredResourceTypesPlainArgs Empty = new GetMonitoredResourceTypesPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy for which  monitored resource types should be listed.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy for which  monitored resource types should be listed.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * Partial response refers to an optimization technique offered by the RESTful web APIs, to return all the information except the fields requested to be excluded (excludeFields) by the client. In this mechanism, the client sends the exclude field names as the query parameters for an API to the server, and the server trims down the default response content by removing the fields that are not required by the client. The parameter controls which fields to exlude and to return and should be a query string parameter called &#34;excludeFields&#34; of an array type, provide the values as enums, and use collectionFormat.
     * 
     */
    @Import(name="excludeFields")
    private @Nullable List<String> excludeFields;

    /**
     * @return Partial response refers to an optimization technique offered by the RESTful web APIs, to return all the information except the fields requested to be excluded (excludeFields) by the client. In this mechanism, the client sends the exclude field names as the query parameters for an API to the server, and the server trims down the default response content by removing the fields that are not required by the client. The parameter controls which fields to exlude and to return and should be a query string parameter called &#34;excludeFields&#34; of an array type, provide the values as enums, and use collectionFormat.
     * 
     */
    public Optional<List<String>> excludeFields() {
        return Optional.ofNullable(this.excludeFields);
    }

    /**
     * Partial response refers to an optimization technique offered by the RESTful web APIs, to return only the information (fields) required by the client. In this mechanism, the client sends the required field names as the query parameters for an API to the server, and the server trims down the default response content by removing the fields that are not required by the client. The parameter controls which fields to return and should be a query string parameter called &#34;fields&#34; of an array type, provide the values as enums, and use collectionFormat.
     * 
     * MonitoredResourceType Id, name and compartment will be added by default.
     * 
     */
    @Import(name="fields")
    private @Nullable List<String> fields;

    /**
     * @return Partial response refers to an optimization technique offered by the RESTful web APIs, to return only the information (fields) required by the client. In this mechanism, the client sends the required field names as the query parameters for an API to the server, and the server trims down the default response content by removing the fields that are not required by the client. The parameter controls which fields to return and should be a query string parameter called &#34;fields&#34; of an array type, provide the values as enums, and use collectionFormat.
     * 
     * MonitoredResourceType Id, name and compartment will be added by default.
     * 
     */
    public Optional<List<String>> fields() {
        return Optional.ofNullable(this.fields);
    }

    @Import(name="filters")
    private @Nullable List<GetMonitoredResourceTypesFilter> filters;

    public Optional<List<GetMonitoredResourceTypesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to exclude system resource types. If set to true, system resource types will be excluded.
     * 
     */
    @Import(name="isExcludeSystemTypes")
    private @Nullable Boolean isExcludeSystemTypes;

    /**
     * @return A filter to exclude system resource types. If set to true, system resource types will be excluded.
     * 
     */
    public Optional<Boolean> isExcludeSystemTypes() {
        return Optional.ofNullable(this.isExcludeSystemTypes);
    }

    /**
     * A filter to return monitored resource types that has the matching namespace.
     * 
     */
    @Import(name="metricNamespace")
    private @Nullable String metricNamespace;

    /**
     * @return A filter to return monitored resource types that has the matching namespace.
     * 
     */
    public Optional<String> metricNamespace() {
        return Optional.ofNullable(this.metricNamespace);
    }

    /**
     * A filter to return monitored resource types that match exactly with the resource type name given.
     * 
     */
    @Import(name="name")
    private @Nullable String name;

    /**
     * @return A filter to return monitored resource types that match exactly with the resource type name given.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * A filter to return only resources that matches with lifecycleState given.
     * 
     */
    @Import(name="status")
    private @Nullable String status;

    /**
     * @return A filter to return only resources that matches with lifecycleState given.
     * 
     */
    public Optional<String> status() {
        return Optional.ofNullable(this.status);
    }

    private GetMonitoredResourceTypesPlainArgs() {}

    private GetMonitoredResourceTypesPlainArgs(GetMonitoredResourceTypesPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.excludeFields = $.excludeFields;
        this.fields = $.fields;
        this.filters = $.filters;
        this.isExcludeSystemTypes = $.isExcludeSystemTypes;
        this.metricNamespace = $.metricNamespace;
        this.name = $.name;
        this.status = $.status;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMonitoredResourceTypesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMonitoredResourceTypesPlainArgs $;

        public Builder() {
            $ = new GetMonitoredResourceTypesPlainArgs();
        }

        public Builder(GetMonitoredResourceTypesPlainArgs defaults) {
            $ = new GetMonitoredResourceTypesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy for which  monitored resource types should be listed.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param excludeFields Partial response refers to an optimization technique offered by the RESTful web APIs, to return all the information except the fields requested to be excluded (excludeFields) by the client. In this mechanism, the client sends the exclude field names as the query parameters for an API to the server, and the server trims down the default response content by removing the fields that are not required by the client. The parameter controls which fields to exlude and to return and should be a query string parameter called &#34;excludeFields&#34; of an array type, provide the values as enums, and use collectionFormat.
         * 
         * @return builder
         * 
         */
        public Builder excludeFields(@Nullable List<String> excludeFields) {
            $.excludeFields = excludeFields;
            return this;
        }

        /**
         * @param excludeFields Partial response refers to an optimization technique offered by the RESTful web APIs, to return all the information except the fields requested to be excluded (excludeFields) by the client. In this mechanism, the client sends the exclude field names as the query parameters for an API to the server, and the server trims down the default response content by removing the fields that are not required by the client. The parameter controls which fields to exlude and to return and should be a query string parameter called &#34;excludeFields&#34; of an array type, provide the values as enums, and use collectionFormat.
         * 
         * @return builder
         * 
         */
        public Builder excludeFields(String... excludeFields) {
            return excludeFields(List.of(excludeFields));
        }

        /**
         * @param fields Partial response refers to an optimization technique offered by the RESTful web APIs, to return only the information (fields) required by the client. In this mechanism, the client sends the required field names as the query parameters for an API to the server, and the server trims down the default response content by removing the fields that are not required by the client. The parameter controls which fields to return and should be a query string parameter called &#34;fields&#34; of an array type, provide the values as enums, and use collectionFormat.
         * 
         * MonitoredResourceType Id, name and compartment will be added by default.
         * 
         * @return builder
         * 
         */
        public Builder fields(@Nullable List<String> fields) {
            $.fields = fields;
            return this;
        }

        /**
         * @param fields Partial response refers to an optimization technique offered by the RESTful web APIs, to return only the information (fields) required by the client. In this mechanism, the client sends the required field names as the query parameters for an API to the server, and the server trims down the default response content by removing the fields that are not required by the client. The parameter controls which fields to return and should be a query string parameter called &#34;fields&#34; of an array type, provide the values as enums, and use collectionFormat.
         * 
         * MonitoredResourceType Id, name and compartment will be added by default.
         * 
         * @return builder
         * 
         */
        public Builder fields(String... fields) {
            return fields(List.of(fields));
        }

        public Builder filters(@Nullable List<GetMonitoredResourceTypesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetMonitoredResourceTypesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isExcludeSystemTypes A filter to exclude system resource types. If set to true, system resource types will be excluded.
         * 
         * @return builder
         * 
         */
        public Builder isExcludeSystemTypes(@Nullable Boolean isExcludeSystemTypes) {
            $.isExcludeSystemTypes = isExcludeSystemTypes;
            return this;
        }

        /**
         * @param metricNamespace A filter to return monitored resource types that has the matching namespace.
         * 
         * @return builder
         * 
         */
        public Builder metricNamespace(@Nullable String metricNamespace) {
            $.metricNamespace = metricNamespace;
            return this;
        }

        /**
         * @param name A filter to return monitored resource types that match exactly with the resource type name given.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable String name) {
            $.name = name;
            return this;
        }

        /**
         * @param status A filter to return only resources that matches with lifecycleState given.
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable String status) {
            $.status = status;
            return this;
        }

        public GetMonitoredResourceTypesPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}