// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LogAnalytics.inputs.GetNamespaceTemplatesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetNamespaceTemplatesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNamespaceTemplatesPlainArgs Empty = new GetNamespaceTemplatesPlainArgs();

    /**
     * The ID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetNamespaceTemplatesFilter> filters;

    public Optional<List<GetNamespaceTemplatesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The template name used for filtering.
     * 
     */
    @Import(name="name")
    private @Nullable String name;

    /**
     * @return The template name used for filtering.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The Logging Analytics namespace used for the request.
     * 
     */
    @Import(name="namespace", required=true)
    private String namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public String namespace() {
        return this.namespace;
    }

    /**
     * filter
     * 
     */
    @Import(name="namespaceTemplateFilter")
    private @Nullable String namespaceTemplateFilter;

    /**
     * @return filter
     * 
     */
    public Optional<String> namespaceTemplateFilter() {
        return Optional.ofNullable(this.namespaceTemplateFilter);
    }

    /**
     * The template lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return The template lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The template display text used for filtering. Only templates with the specified name or description will be returned.
     * 
     */
    @Import(name="templateDisplayText")
    private @Nullable String templateDisplayText;

    /**
     * @return The template display text used for filtering. Only templates with the specified name or description will be returned.
     * 
     */
    public Optional<String> templateDisplayText() {
        return Optional.ofNullable(this.templateDisplayText);
    }

    /**
     * The template type used for filtering. Only templates of the specified type will be returned.
     * 
     */
    @Import(name="type")
    private @Nullable String type;

    /**
     * @return The template type used for filtering. Only templates of the specified type will be returned.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }

    private GetNamespaceTemplatesPlainArgs() {}

    private GetNamespaceTemplatesPlainArgs(GetNamespaceTemplatesPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.name = $.name;
        this.namespace = $.namespace;
        this.namespaceTemplateFilter = $.namespaceTemplateFilter;
        this.state = $.state;
        this.templateDisplayText = $.templateDisplayText;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNamespaceTemplatesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNamespaceTemplatesPlainArgs $;

        public Builder() {
            $ = new GetNamespaceTemplatesPlainArgs();
        }

        public Builder(GetNamespaceTemplatesPlainArgs defaults) {
            $ = new GetNamespaceTemplatesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetNamespaceTemplatesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetNamespaceTemplatesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param name The template name used for filtering.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable String name) {
            $.name = name;
            return this;
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespaceTemplateFilter filter
         * 
         * @return builder
         * 
         */
        public Builder namespaceTemplateFilter(@Nullable String namespaceTemplateFilter) {
            $.namespaceTemplateFilter = namespaceTemplateFilter;
            return this;
        }

        /**
         * @param state The template lifecycle state used for filtering. Currently supported values are ACTIVE and DELETED.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        /**
         * @param templateDisplayText The template display text used for filtering. Only templates with the specified name or description will be returned.
         * 
         * @return builder
         * 
         */
        public Builder templateDisplayText(@Nullable String templateDisplayText) {
            $.templateDisplayText = templateDisplayText;
            return this;
        }

        /**
         * @param type The template type used for filtering. Only templates of the specified type will be returned.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable String type) {
            $.type = type;
            return this;
        }

        public GetNamespaceTemplatesPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetNamespaceTemplatesPlainArgs", "compartmentId");
            }
            if ($.namespace == null) {
                throw new MissingRequiredPropertyException("GetNamespaceTemplatesPlainArgs", "namespace");
            }
            return $;
        }
    }

}
