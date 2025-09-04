import core.file_interaction as fi
import core.technology_switch as tech_sw
import output_generators.traceability as traceability


def detect_authentication_scopes(microservices: dict, dfd) -> dict:
    """Detects authentication scopes via HttpSecurity configurations.
    """

    configuration_tuples = detect_configurations(dfd)
    microservices = interpret_configurations(microservices, configuration_tuples)

    return microservices


def detect_configurations(dfd):
    """Finds httpSecurity configurations.
    """

    configuration_tuples = list()
    configuration_classes = ["AuthenticationManagerBuilder", "HttpSecurity"]
    for c_class in configuration_classes:
        results = fi.search_keywords(c_class, file_extension=["*.java", "*.kt"])
        for r in results.keys():
            microservice = tech_sw.detect_microservice(results[r]["path"], dfd)
            configurations = set()
            objects = list()
            for line in results[r]["content"]:
                if "configure(" + c_class in line:
                    objects.append(line.split(c_class)[1].split(")")[0].strip())
            for object in objects:
                if object:
                    for line_nr in range(len(results[r]["content"])):
                        line = results[r]["content"][line_nr]
                        configuration = False
                        if object in line:
                            if ";" in line:
                                configuration = line.split(object)[1].split(";")[0].strip(" .")
                            else:   # multi-line
                                found = False
                                counter = line_nr
                                configuration = line.strip()

                                while not found and counter < len(results[r]["content"]) - 1:
                                    counter += 1
                                    new_line = results[r]["content"][counter]
                                    new_line = new_line.strip()

                                    if not new_line.strip()[0:2] == "//":
                                        new_configuration = configuration + new_line
                                        configuration = new_configuration

                                    if ";" in new_line:
                                        found = True

                        if configuration:
                            configuration = configuration.replace(" ", "")
                            if "{" in configuration:
                                configuration = configuration.split("{")[1]
                            if object + "." in configuration:
                                configurations.add((configuration, results[r]["path"], results[r]["line_nr"], results[r]["span"]))
            configuration_tuples.append((microservice, configurations))

    return configuration_tuples


def interpret_configurations(microservices: dict, configuration_tuples: list) -> dict:
    """Translates configurations into stereotypes and tagged values.
    """

    for configuration_tuple in configuration_tuples:
        stereotypes, tagged_values = list(), list()
        # create stereotypes and tagged_values
        for configuration in configuration_tuple[1]:

            scope_restricted = False
            # CSRF
            if "csrf().disable()" in configuration[0] or "csrf.disable()" in configuration[0]:
                stereotypes.append("csrf_disabled")

                traceability.add_trace({
                    "parent_item": configuration_tuple[0],
                    "item": "csrf_disabled",
                    "file": configuration[1],
                    "line": configuration[2],
                    "span": configuration[3]
                })
            # unauthenticated access
            if "permitAll()" in configuration[0]:
                scope_restricted = True
            # Basic atuhentication
            if "httpBasic()" in configuration[0]:
                stereotypes.append("basic_authentication")
                
                traceability.add_trace({
                    "parent_item": configuration_tuple[0],
                    "item": "basic_authentication",
                    "file": configuration[1],
                    "line": configuration[2],
                    "span": configuration[3]
                })
            # In Memory authentication
            if "inMemoryAuthentication()" in configuration[0]:
                stereotypes.append("in_memory_authentication")

                traceability.add_trace({
                    "parent_item": configuration_tuple[0],
                    "item": "in_memory_authentication",
                    "file": configuration[1],
                    "line": configuration[2],
                    "span": configuration[3]
                })
            # Authentication credentials
            if "withUser(" in configuration[0]:
                username = configuration[0].split("withUser(")[1].split(")")[0].strip("\" ")
                tagged_values.append(("Username", username))
            if "password(" in configuration[0]:
                password = configuration[0].split("password(")[1].split(")")[0].strip("\" ")
                tagged_values.append(("Password", password))
            # Authentication scope
            if "anyRequest().authenticated()" in configuration[0] and not scope_restricted:
                stereotypes.append("authentication_scope_all_requests")

                traceability.add_trace({
                    "parent_item": configuration_tuple[0],
                    "item": "authentication_scope_all_requests",
                    "file": configuration[1],
                    "line": configuration[2],
                    "span": configuration[3]
                })

        for m in microservices.values():
            if m["name"] == configuration_tuple[0]:
                m.setdefault("stereotype_instances",[]).extend(stereotypes)
                m.setdefault("tagged_values",[]).extend(tagged_values)

    return microservices
