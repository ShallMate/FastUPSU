if(NOT DEFINED SOURCE_DIR OR NOT DEFINED PATCH_FILE)
  message(FATAL_ERROR "SOURCE_DIR and PATCH_FILE are required")
endif()
execute_process(COMMAND git apply --check --ignore-whitespace "${PATCH_FILE}"
                WORKING_DIRECTORY "${SOURCE_DIR}" RESULT_VARIABLE can_apply)
if(can_apply EQUAL 0)
  execute_process(COMMAND git apply --ignore-whitespace "${PATCH_FILE}"
                  WORKING_DIRECTORY "${SOURCE_DIR}" RESULT_VARIABLE applied)
  if(NOT applied EQUAL 0)
    message(FATAL_ERROR "failed to apply ${PATCH_FILE}")
  endif()
else()
  execute_process(COMMAND git apply --reverse --check --ignore-whitespace "${PATCH_FILE}"
                  WORKING_DIRECTORY "${SOURCE_DIR}" RESULT_VARIABLE already_applied)
  if(NOT already_applied EQUAL 0)
    message(FATAL_ERROR "patch neither applies nor is already applied: ${PATCH_FILE}")
  endif()
endif()
