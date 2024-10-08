// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataIntegration.inputs.GetWorkspaceProjectsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetWorkspaceProjectsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetWorkspaceProjectsPlainArgs Empty = new GetWorkspaceProjectsPlainArgs();

    /**
     * Specifies the fields to get for an object.
     * 
     */
    @Import(name="fields")
    private @Nullable List<String> fields;

    /**
     * @return Specifies the fields to get for an object.
     * 
     */
    public Optional<List<String>> fields() {
        return Optional.ofNullable(this.fields);
    }

    @Import(name="filters")
    private @Nullable List<GetWorkspaceProjectsFilter> filters;

    public Optional<List<GetWorkspaceProjectsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Used to filter by the identifier of the object.
     * 
     */
    @Import(name="identifiers")
    private @Nullable List<String> identifiers;

    /**
     * @return Used to filter by the identifier of the object.
     * 
     */
    public Optional<List<String>> identifiers() {
        return Optional.ofNullable(this.identifiers);
    }

    /**
     * Used to filter by the name of the object.
     * 
     */
    @Import(name="name")
    private @Nullable String name;

    /**
     * @return Used to filter by the name of the object.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * This parameter can be used to filter objects by the names that match partially or fully with the given value.
     * 
     */
    @Import(name="nameContains")
    private @Nullable String nameContains;

    /**
     * @return This parameter can be used to filter objects by the names that match partially or fully with the given value.
     * 
     */
    public Optional<String> nameContains() {
        return Optional.ofNullable(this.nameContains);
    }

    /**
     * The workspace ID.
     * 
     */
    @Import(name="workspaceId", required=true)
    private String workspaceId;

    /**
     * @return The workspace ID.
     * 
     */
    public String workspaceId() {
        return this.workspaceId;
    }

    private GetWorkspaceProjectsPlainArgs() {}

    private GetWorkspaceProjectsPlainArgs(GetWorkspaceProjectsPlainArgs $) {
        this.fields = $.fields;
        this.filters = $.filters;
        this.identifiers = $.identifiers;
        this.name = $.name;
        this.nameContains = $.nameContains;
        this.workspaceId = $.workspaceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetWorkspaceProjectsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetWorkspaceProjectsPlainArgs $;

        public Builder() {
            $ = new GetWorkspaceProjectsPlainArgs();
        }

        public Builder(GetWorkspaceProjectsPlainArgs defaults) {
            $ = new GetWorkspaceProjectsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param fields Specifies the fields to get for an object.
         * 
         * @return builder
         * 
         */
        public Builder fields(@Nullable List<String> fields) {
            $.fields = fields;
            return this;
        }

        /**
         * @param fields Specifies the fields to get for an object.
         * 
         * @return builder
         * 
         */
        public Builder fields(String... fields) {
            return fields(List.of(fields));
        }

        public Builder filters(@Nullable List<GetWorkspaceProjectsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetWorkspaceProjectsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param identifiers Used to filter by the identifier of the object.
         * 
         * @return builder
         * 
         */
        public Builder identifiers(@Nullable List<String> identifiers) {
            $.identifiers = identifiers;
            return this;
        }

        /**
         * @param identifiers Used to filter by the identifier of the object.
         * 
         * @return builder
         * 
         */
        public Builder identifiers(String... identifiers) {
            return identifiers(List.of(identifiers));
        }

        /**
         * @param name Used to filter by the name of the object.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable String name) {
            $.name = name;
            return this;
        }

        /**
         * @param nameContains This parameter can be used to filter objects by the names that match partially or fully with the given value.
         * 
         * @return builder
         * 
         */
        public Builder nameContains(@Nullable String nameContains) {
            $.nameContains = nameContains;
            return this;
        }

        /**
         * @param workspaceId The workspace ID.
         * 
         * @return builder
         * 
         */
        public Builder workspaceId(String workspaceId) {
            $.workspaceId = workspaceId;
            return this;
        }

        public GetWorkspaceProjectsPlainArgs build() {
            if ($.workspaceId == null) {
                throw new MissingRequiredPropertyException("GetWorkspaceProjectsPlainArgs", "workspaceId");
            }
            return $;
        }
    }

}
